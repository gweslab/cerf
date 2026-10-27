from __future__ import annotations

from typing import Callable


def tagged(tag: str) -> Callable[[str], None]:
    def say(text: str) -> None:
        print("[{}] {}".format(tag, text), flush=True)
    return say
