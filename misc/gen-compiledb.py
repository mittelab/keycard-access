#!/usr/bin/env python3
import sys
import os
import json
import subprocess
import glob
import re


_RGX_CDB = re.compile(r'Building compilation database (?P<path>.*?\bcompile_commands\.json)')


def main(args):
    pio_ini_path = os.path.join(args.platformio_ini, 'platformio.ini') \
        if os.path.isdir(args.platformio_ini) else args.platformio_ini
    cdb_dest_path = args.destination

    if not os.path.isfile(pio_ini_path):
        sys.exit(f'Cannot find {pio_ini_path}')

    pio_ini_dir = os.path.dirname(pio_ini_path)

    print(f'Running pio run -t compiledb on {pio_ini_path}')
    build_p = subprocess.Popen('pio run -t compiledb'.split(),
                               stdout=subprocess.PIPE,
                               universal_newlines=True,  # Note: needed for getting textual output
                               cwd=pio_ini_dir)

    # Scan the output to find where did platformio put the compiledb
    cdb_source_path = None
    for line in build_p.stdout:
        for m in _RGX_CDB.finditer(line):
            cdb_source_path = m.group('path')
        if cdb_source_path is not None:
            break
    if (return_code := build_p.wait(30.)) != 0:
        print(f'Failed with exit code {return_code}.', file=sys.stderr)
        sys.exit(return_code)

    # Make sure the input compilation db exists
    if not os.path.isabs(cdb_source_path):
        cdb_source_path = os.path.join(pio_ini_dir, cdb_source_path)
    if not os.path.isfile(cdb_source_path):
        sys.exit(f'Compilation DB was not created at {cdb_source_path}')

    # Read the cdb and load the entries
    print(f'Filtering compiledb entries from {cdb_source_path}')
    with open(cdb_source_path, 'r') as fp:
        cdb = json.load(fp)

    dot_pio_dir = os.path.join(pio_ini_dir, '.pio').lower()
    proj_dir = os.getcwd().lower()

    def _filter_entry(entry):
        file = entry.get('file', '').lower()
        return file.startswith(proj_dir) and not file.startswith(dot_pio_dir)

    cdb = list(filter(_filter_entry, cdb))

    print(f'Writing {cdb_dest_path}.')
    with open(cdb_dest_path, 'w') as fp:
        json.dump(cdb, fp, indent=4)

    for cmakelists_txt in glob.iglob(os.path.join(pio_ini_dir, '**', 'CMakeLists.txt'), recursive=True):
        if os.path.isfile(cmakelists_txt):
            print(f'Removing {cmakelists_txt}.')
            os.unlink(cmakelists_txt)


if __name__ == '__main__':
    from argparse import ArgumentParser
    parser = ArgumentParser('Generates a nicely filtered compiled_commands.json for a platformio project.')
    parser.add_argument('platformio_ini', help='Platformio.ini file (or its directory).')
    parser.add_argument('--destination', default='compile_commands.json', help='Destination compile_commands.json.')
    main(parser.parse_args())

