from __future__ import annotations

import sys
from typing import Callable, List, Optional, Tuple, Type


def option(argv: List[str], name: str) -> Optional[str]:
    prefix = name + "="
    return next((a[len(prefix):] for a in argv if a.startswith(prefix)), None)


def run_main(main: Callable[[List[str]], int], errors: Tuple[Type[BaseException], ...]) -> None:
    try:
        raise SystemExit(main(sys.argv[1:]))
    except errors as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        raise SystemExit(1)
