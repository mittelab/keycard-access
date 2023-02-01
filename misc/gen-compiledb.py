#!/usr/bin/env python3
import sys
import os
import json
import subprocess
import glob
import re
import git
from typing import Optional

_RGX_CDB = re.compile(r'Building compilation database (?P<path>.*?\bcompile_commands\.json)')


def in_work_tree(repo: git.Repo, file: str, rel_to: Optional[str] = None) -> bool:
    if not os.path.isabs(file):
        file = os.path.join(rel_to, file)
    file = os.path.realpath(file)
    if not file.startswith(repo.working_dir):
        return False
    file = os.path.relpath(file, repo.working_dir)
    rsub = repo.head.commit.tree
    for piece in os.path.dirname(file).split(os.sep):
        try:
            rsub = rsub[piece]
        except TypeError:
            for submodule in repo.submodules:
                if submodule.abspath == rsub.abspath:
                    return in_work_tree(git.Repo(submodule.abspath), file, repo.working_dir)
        except KeyError:
            return False
    return file in rsub


def cdb_patch_argument(arg: str, old_d: str, new_d: str) -> str:
    arg_pfx = ''
    if arg.startswith('-'):
        for pfx in ['-I', '-iquote', '-o']:
            if arg.startswith(pfx):
                arg_pfx = pfx
                arg = arg[len(pfx):]
                break
    if len(arg) > 0:
        if not os.path.isabs(arg):
            candidate = os.path.join(old_d, arg)
            if os.path.exists(candidate):
                candidate = os.path.realpath(candidate)
                arg = os.path.relpath(candidate, new_d)
        elif os.path.exists(arg):
            arg = os.path.realpath(arg)
    return arg_pfx + arg


def cdb_change_entry_path(e: dict, new_d: str) -> dict:
    cmd = e['command']
    old_d = e['directory']
    file = e['file']
    assert os.path.isabs(file)
    assert os.path.isabs(old_d)
    new_d = os.path.abspath(new_d)
    return {
        'command': ' '.join(map(lambda a: cdb_patch_argument(a, old_d, new_d), cmd.split())),
        'directory': new_d,
        'file': os.path.realpath(file)
    }


def main(args):
    pio_ini_path = os.path.join(args.platformio_ini, 'platformio.ini') \
        if os.path.isdir(args.platformio_ini) else args.platformio_ini
    cdb_dest_path = os.path.abspath(args.destination)

    if not os.path.isfile(pio_ini_path):
        sys.exit(f'Cannot find {pio_ini_path}')

    pio_ini_dir = os.path.dirname(pio_ini_path)

    print(f'Running pio run -t compiledb on {pio_ini_path}')
    build_p = subprocess.Popen(os.path.expanduser('~/.platformio/penv/bin/pio run -t compiledb').split(),
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

    dest_dir = os.path.dirname(cdb_dest_path)
    dest_repo = git.Repo(dest_dir, search_parent_directories=True)
    cdb = list(
        map(lambda e: cdb_change_entry_path(e, dest_dir),
            filter(lambda e: in_work_tree(dest_repo, e['file'], rel_to=pio_ini_dir),
                   cdb)))

    if os.path.isfile(cdb_dest_path):
        print(f'Merging into {cdb_dest_path}.')
        entries = {}
        with open(cdb_dest_path, 'r') as fp:
            entries = dict({e['file']: e for e in json.load(fp)})
        for e in cdb:
            entries[e['file']] = e
        cdb = list(entries.values())

    print(f'Writing {cdb_dest_path}.')
    with open(cdb_dest_path, 'w') as fp:
        json.dump(cdb, fp, indent=4)

    os.unlink(cdb_source_path)


if __name__ == '__main__':
    from argparse import ArgumentParser

    parser = ArgumentParser('Generates a nicely filtered compiled_commands.json for a platformio project.')
    parser.add_argument('platformio_ini', help='Platformio.ini file (or its directory).')
    parser.add_argument('--destination', default='compile_commands.json', help='Destination compile_commands.json.')
    main(parser.parse_args())
