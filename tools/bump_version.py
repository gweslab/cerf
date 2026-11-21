#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import changelog
import version_header

CHANGELOG_YML = Path(changelog.CHANGELOG_YML)
FIRST_ENTRY = re.compile(r"^- version:", re.MULTILINE)
PLACEHOLDER = ("- version: {}\n"
               "  date: TBA\n"
               "  changes: |\n"
               "    No user affecting changes yet\n"
               "\n")


def bumped(version: List[int], part: str) -> List[int]:
    index = version_header.RELEASE_PARTS.index(part)
    return version[:index] + [version[index] + 1] + [0] * (len(version) - index - 1)


def open_changelog_entry(series: str) -> str:
    label = f"v{series}"
    if changelog.entry_for(series) is not None:
        raise SystemExit(f"{CHANGELOG_YML.name} already has an entry for {label}")
    text = CHANGELOG_YML.read_text(encoding="utf-8")
    start = FIRST_ENTRY.search(text).start()
    CHANGELOG_YML.write_bytes((text[:start] + PLACEHOLDER.format(label) + text[start:]).encode("utf-8"))
    return label


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(description="Bump the CERF version in cerf-qt/version.h.")
    parser.add_argument("part", choices=version_header.RELEASE_PARTS,
                        help="patch: add 1 to the patch number. "
                             "minor: add 1 to the minor number, set the patch number to 0 "
                             "and add a placeholder entry to docs/changelog.yml. "
                             "major: add 1 to the major number, set the other numbers to 0 "
                             "and add a placeholder entry to docs/changelog.yml.")
    part = parser.parse_args(argv).part

    old = version_header.release_numbers()
    new = bumped(old, part)
    if part != "patch":
        label = open_changelog_entry(f"{new[0]}.{new[1]}")
        print(f"{CHANGELOG_YML.name}: added the {label} entry")
    version_header.rewrite(dict(zip(version_header.RELEASE_PARTS, map(str, new))))
    print("version.h: {} -> {}".format(".".join(map(str, old)), ".".join(map(str, new))))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
