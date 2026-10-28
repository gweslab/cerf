from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from json_files import write_json

NAME = "cerf.local.json"


class LocalConfigError(Exception):
    pass


def overlay_for(root: Path, mode: str) -> Optional[Path]:
    path = root / "bundled" / NAME
    return path if mode == "dev" and path.is_file() else None


def merge(cerf_json: Path, overlay: Path) -> None:
    merged = _object(cerf_json)
    merged.update(_object(overlay))
    write_json(cerf_json, merged)


def _object(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except ValueError as exc:
        raise LocalConfigError("{}: {}".format(path, exc))
    if not isinstance(value, dict):
        raise LocalConfigError("{} holds no JSON object".format(path))
    return value


def main(argv: List[str]) -> int:
    if len(argv) == 4 and argv[1] == "--merge":
        try:
            merge(Path(argv[2]), Path(argv[3]))
        except LocalConfigError as exc:
            sys.stderr.write("{}\n".format(exc))
            return 1
        return 0
    sys.stderr.write("usage: local_config.py --merge <cerf.json> <overlay>\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
