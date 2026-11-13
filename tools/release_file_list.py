#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from product_facts import INSTALLED_FILES_KEY, INSTALLED_FILES_NAME


def release_files(folder: Path) -> List[str]:
    files = []
    for directory, dirnames, filenames in os.walk(str(folder)):
        base = Path(directory)
        for name in dirnames + filenames:
            path = base / name
            if path.is_symlink() or path.is_file():
                files.append(path.relative_to(folder).as_posix())
    return sorted(name for name in files if name != INSTALLED_FILES_NAME)


def write_list(folder: Path) -> None:
    text = json.dumps({INSTALLED_FILES_KEY: release_files(folder)}, indent=2) + "\n"
    with open(str(folder / INSTALLED_FILES_NAME), "w", encoding="utf-8", newline="\n") as out:
        out.write(text)


def main(argv: List[str]) -> int:
    if len(argv) != 1:
        print("usage: release_file_list.py <release folder>", file=sys.stderr)
        return 2
    write_list(Path(argv[0]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
