from __future__ import annotations

import os
from typing import Iterable


def write_github_output(lines: Iterable[str]) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as f:
        f.write("".join(line + "\n" for line in lines))
