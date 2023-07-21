
#!/usr/bin/env python3
from typing import Any, Callable
import os

env: Any
Import: Callable

Import('env')


def main():
    project_dir = env['PROJECT_DIR']
    project_name = env.GetProjectOption("custom_project_name")
    if not project_name:
        project_name = 'keycard-access'
    project_name_txt = os.path.join(project_dir, 'project_name.txt')
    with open(project_name_txt, 'wt') as fp:
        print(project_name, file=fp)
    print(f'custom_project_name: set to {project_name} in {project_name_txt}')


main()
