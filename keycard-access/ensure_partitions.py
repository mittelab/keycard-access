#!/usr/bin/env python3
import csv
from typing import Any, Callable, List, Dict, NamedTuple, Optional, Tuple
import os
import json
import sys

try:
    from platformio.proc import exec_command
    from SCons.Script import COMMAND_LINE_TARGETS
except ImportError:
    pass

env: Any
Import: Callable
exec_command: Callable[[List], Dict]
get_python_exe: Callable[[], str]
Import('env')


class PartitionRange(NamedTuple):
    offset: int
    size: int


def read_sdkconfig() -> Dict:
    sdkconfig_json = os.path.join(env.subst('$BUILD_DIR'), 'config', 'sdkconfig.json')
    if not os.path.isfile(sdkconfig_json):
        print('ensure_partitions: warning, could not find "sdkconfig.json" file', file=sys.stderr)
    with open(sdkconfig_json, 'r') as fp:
        return json.load(fp)


def query_parttool(partition_table_partition: PartitionRange, framework_dir: str, partitions_csv: str,
                   part_type_subtype: Optional[Tuple[str, str]] = None) -> Optional[PartitionRange]:
    cmd = [
        env.subst('$PYTHONEXE'),
        os.path.join(framework_dir, 'components', 'partition_table', 'parttool.py'),
        '-q',
        '--partition-table-offset', hex(partition_table_partition.offset),
        '--partition-table-file', partitions_csv,
        'get_partition_info',
        '--info', 'offset', 'size'
    ]
    if part_type_subtype is None:
        cmd.append('--partition-boot-default')
    else:
        cmd.extend(['--partition-type', part_type_subtype[0], '--partition-subtype', part_type_subtype[1]])

    if (r := exec_command(cmd))['returncode'] != 0:
        print('ensure_partitions: error, unable to call ESP-IDF\'s parttool.py', file=sys.stderr)
        print(r['out'], file=sys.stderr)
        print(r['err'], file=sys.stderr)
        return None
    else:
        pieces = r['out'].strip().split(maxsplit=1)
        if len(pieces) < 2:
            return None
        return PartitionRange(*map(lambda ns: int(ns, 16), pieces))


def get_boot_partition(partition_table_partition: PartitionRange, framework_dir: str,
                       partitions_csv: str) -> PartitionRange:
    if (p := query_parttool(partition_table_partition, framework_dir, partitions_csv)) is None:
        print(f'ensure_partitions: error, parttool was unable to determine the boot partition from {partitions_csv}',
              file=sys.stderr)
        env.Exit(1)
        sys.exit(1)
    return p


def get_otadata_partition(partition_table_partition: PartitionRange, framework_dir: str,
                          partitions_csv: str) -> Optional[PartitionRange]:
    return query_parttool(partition_table_partition, framework_dir, partitions_csv, ('data', 'ota'))


def get_bootloader_partition(partition_table_partition: PartitionRange, board: Any) -> PartitionRange:
    mcu = board.get('build.mcu', 'esp32')
    ofs = board.get('upload.bootloader_offset', 0 if mcu in ('esp32c3', 'esp32s3') else 0x1000)
    # https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/partition-tables.html#partition-size-checks
    # The bootloader must fit before the partitions table
    return PartitionRange(offset=ofs, size=max(0, partition_table_partition.offset - ofs))


def get_partition_table_partition(sdkconfig: Dict) -> PartitionRange:
    ofs = sdkconfig.get('PARTITION_TABLE_OFFSET', 0x8000)
    # Fixed size: https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/partition-tables.html#overview
    return PartitionRange(offset=ofs, size=0x1000)


def test_unsupported_partitions(partitions_csv: str):
    with open(partitions_csv, 'r') as fp:
        reader = csv.reader(fp, delimiter=',')
        for row in reader:  # type: Tuple[str]
            row = tuple(map(str.strip, row))
            if row[0].startswith('#'):
                continue
            if len(row) != 6:
                print(f'ensure_partitions: warning, invalid partition table entry: {row}', file=sys.stderr)
                continue
            part_type, part_subtype = row[1:3]
            if part_type == 'data':
                if part_subtype in ('ota', 'nvs', 'phy', 'nvs_keys'):
                    # These either do not require flashing, or they are correctly handled below (e.g. ota data)
                    continue
            elif part_type == 'app':
                if part_subtype == 'factory' or part_subtype.startswith('ota_'):
                    # These are factory or ota partitions, parttool tells us which one we have to write to, the others
                    # are irrelevant.
                    continue
            print(f'ensure_partitions: warning, partition {row[0]} of type {part_type} ({part_subtype}) will not be '
                  f'flashed because building is skipped (-t nobuild)!', file=sys.stderr)


def main():
    if 'nobuild' not in COMMAND_LINE_TARGETS:
        print(f'ensure_partitions: info, build is not skipped, all partitions will be built and flashed, I hope.')
        return

    board: Any = env.BoardConfig()
    platform: Any = env.PioPlatform()

    framework_dir: str = platform.get_package_dir('framework-espidf')
    framework_partitions_dir: str = os.path.join(framework_dir, 'components', 'partition_table')
    partitions_csv: str = board.get('build.partitions', 'partitions_singleapp.csv')

    # Get an abs path
    if os.path.isfile(partitions_csv_candidate := os.path.join(framework_partitions_dir, partitions_csv)):
        partitions_csv = partitions_csv_candidate

    # Obtain the three main partitions
    part_partitions_table = get_partition_table_partition(read_sdkconfig())
    part_bootloader = get_bootloader_partition(part_partitions_table, board)
    part_boot_app = get_boot_partition(part_partitions_table, framework_dir, partitions_csv)
    part_ota_data = get_otadata_partition(part_partitions_table, framework_dir, partitions_csv)

    # Make sure the user knows what is not handled
    test_unsupported_partitions(partitions_csv)

    # Build the list of "extra" images to flash
    flash_extra_images = [
        (hex(part_bootloader.offset), os.path.join('$BUILD_DIR', 'bootloader.bin')),
        (hex(part_partitions_table.offset), os.path.join('$BUILD_DIR', 'partitions.bin')),
    ]

    if part_ota_data:
        flash_extra_images.append((hex(part_ota_data.offset), os.path.join('$BUILD_DIR', 'ota_data_initial.bin')))

    print(f'ensure_partitions: info, FLASH_EXTRA_IMAGES {flash_extra_images}')
    print(f'ensure_partitions: info, ESP32_APP_OFFSET {hex(part_boot_app.offset)}')

    # Patch the environment
    env.Prepend(FLASH_EXTRA_IMAGES=flash_extra_images)
    env.Replace(ESP32_APP_OFFSET=hex(part_boot_app.offset))

    # Add some white space
    print('')


main()
