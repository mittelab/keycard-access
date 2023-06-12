#!/usr/bin/env python3
import subprocess
import os
import shutil
import sys


def main():
    proj_dir = os.path.dirname(sys.argv[0])
    version_txt = os.path.join(proj_dir, 'version.txt')
    git = shutil.which('git')
    version_content = 'unknown'
    if git is None:
        print('set_version: unable to find git executable.', file=sys.stderr)
    else:
        r = subprocess.run([git, 'describe', '--tags', '--match', 'v*.*.*'],
                           stdout=subprocess.PIPE, stderr=sys.stderr, universal_newlines=True)
        if r.returncode == 0:
            version_content = r.stdout
            print(f'set_version: version set to {version_content}')
        else:
            print(f'set_version: git describe returned {r.returncode}', file=sys.stderr)

    with open(version_txt, 'wt') as fp:
        print(version_content, file=fp)


main()
