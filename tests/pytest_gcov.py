import pytest
import sys

if __name__ == '__main__':
    pytest.main()
    sys.exit(0)

from enum import Enum
import os.path
from pytest_embedded.unity import TestSuite, TestCase
import re
from pytest_embedded_idf import IdfDut
from pytest_embedded_jtag import OpenOcd

LIBSPOOKY_OBJ_FOLDER = 'esp-idf/libspookyaction/CMakeFiles/__idf_libspookyaction.dir'
GCDA_FOLDERS = ('desfire', 'desfire/esp32', 'pn532', 'pn532/esp32')

# https://stackoverflow.com/a/14693789/1749822
RE_ANSI = re.compile(br'\x1B[@-Z\\-_]|[\x80-\x9A\x9C-\x9F]|(?:\x1B\[|\x9B)[0-?]*[ -/]*[@-~]')
RE_SECT_COMPLETE = re.compile(br'^\s*SECT\s+(PASS|FAIL|SKIP)\s+(.+?)$')


class TestResult(Enum):
    PASS = 'PASS'
    FAIL = 'FAIL'
    SKIP = 'SKIP'

    def to_unity_testcase_result(self) -> str:
        return {self.PASS: 'PASS', self.FAIL: 'FAIL', self.SKIP: 'IGNORE'}[self]


def collect_testcase(ts: TestSuite, name: str, result: TestResult):
    tc = TestCase(name, result.to_unity_testcase_result())
    ts.testcases.append(tc)
    ts.attrs['tests'] += 1
    if result is TestResult.FAIL:
        ts.attrs['failures'] += 1
    elif result is TestResult.SKIP:
        ts.attrs['skipped'] += 1


def _dump_coverage(openocd: OpenOcd, cmd: str) -> None:
    response = openocd.write(cmd)

    expect_lines = [
        'Targets connected.',
        'Targets disconnected.',
    ]

    for line in response.splitlines():
        for expect in expect_lines[:]:
            if expect in line:
                if expect.endswith('.gcda'):  # check file exists
                    file_path = line.split()[3].strip("'")
                    assert os.path.isfile(file_path)

                expect_lines.remove(expect)

    assert len(expect_lines) == 0


@pytest.mark.parametrize(
    'embedded_services, no_gdb',
    [
        ('esp,idf,jtag', 'y'),
    ],
    indirect=True,
)
def test_gcov(dut: IdfDut, openocd: OpenOcd, embedded_services, no_gdb) -> None:
    # create the generated .gcda folder, otherwise would have error: failed to open file.
    # normally this folder would be created via `idf.py build`. but in CI the non-related files would not be preserved
    # TODO: for gcda_folder in GCDA_FOLDERS:
    # TODO:     os.makedirs(os.path.join(dut.app.binary_path, LIBSPOOKY_OBJ_FOLDER, gcda_folder), exist_ok=True)

    testsuite: TestSuite = dut.testsuite

    while True:
        m = dut.expect('.*?\n', timeout=30)  # type: re.Match
        if m is None:
            continue
        line = m.group(0).strip()
        # Remove all ansi codes
        line = RE_ANSI.sub(b'', line)
        if (m := RE_SECT_COMPLETE.match(line)) is not None:
            section_name = m.group(2).decode()
            section_result = m.group(1).decode()
            collect_testcase(testsuite, section_name, TestResult(section_result))
        elif b'main_task: Returned from app_main()' in line:
            break

    # Test two hard-coded dumps
    # TODO: _dump_coverage(openocd, 'esp gcov')
