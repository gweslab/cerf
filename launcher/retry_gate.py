from __future__ import annotations

from typing import Callable, Optional, Tuple, Type

RetryFn = Callable[[str, str], bool]


def attempt(title: str, action_text: str, action: Callable[[], object],
            ask_retry: RetryFn,
            errors: Tuple[Type[BaseException], ...] = (OSError,)
            ) -> Optional[BaseException]:
    while True:
        try:
            action()
            return None
        except errors as exc:
            if not ask_retry(title, "{} failed:\n{}\n\nRetry?".format(
                    action_text, exc)):
                return exc
