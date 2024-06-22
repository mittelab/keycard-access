import pytest
import types
import sys
from pytest_embedded_jtag import OpenOcd

from pytest_embedded_idf import IdfDut
from typing import Iterable


# Or sys.path.extend('thirdparty/spooky_reporter'); from spooky_test import parse_test_lines
def _import_spooky_test() -> types.ModuleType:
    from importlib.util import spec_from_file_location, module_from_spec
    spec = spec_from_file_location('spooky_test', 'thirdparty/spooky_reporter/spooky_test.py')
    mod = module_from_spec(spec)
    sys.modules['spooky_test'] = mod
    spec.loader.exec_module(mod)
    return mod


spooky_test = _import_spooky_test()


def parse_test_lines(dut: IdfDut, timeout: float = 30, strip_ansi: bool = True) -> Iterable[bytes]:
    pass


# noinspection PyRedeclaration
parse_test_lines = spooky_test.parse_test_lines

if __name__ == '__main__':
    pytest.main()
    sys.exit(0)


@pytest.mark.parametrize(
    'embedded_services, no_gdb',
    [
        ('esp,idf', 'y'),
    ],
    indirect=True,
)
def test_gcov(dut: IdfDut, embedded_services, no_gdb) -> None:
    for line in parse_test_lines(dut, strip_ansi=True):
        if b'main_task: Returned from app_main()' in line:
            break
