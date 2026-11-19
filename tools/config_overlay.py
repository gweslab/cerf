from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from json_files import write_json

LOCAL_NAME = "cerf.local.json"
UNSTABLE_NAME = "cerf.unstable.json"
NAMES = (LOCAL_NAME, UNSTABLE_NAME)


class ConfigOverlayError(Exception):
    pass


def overlay_for(root: Path, mode: str, unstable: bool) -> Optional[Path]:
    bundled = root / "bundled"
    if mode == "dev":
        local = bundled / LOCAL_NAME
        return local if local.is_file() else None
    return bundled / UNSTABLE_NAME if unstable else None


def merge(cerf_json: Path, overlay: Path) -> None:
    merged = _object(cerf_json) if cerf_json.is_file() else {}
    merged.update(_object(overlay))
    write_json(cerf_json, merged)


def _object(path: Path) -> Dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except ValueError as exc:
        raise ConfigOverlayError("{}: {}".format(path, exc))
    if not isinstance(value, dict):
        raise ConfigOverlayError("{} holds no JSON object".format(path))
    return value


def main(argv: List[str]) -> int:
    if len(argv) == 4 and argv[1] == "--merge":
        try:
            merge(Path(argv[2]), Path(argv[3]))
        except ConfigOverlayError as exc:
            sys.stderr.write("{}\n".format(exc))
            return 1
        return 0
    sys.stderr.write("usage: config_overlay.py --merge <cerf.json> <overlay>\n")
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
