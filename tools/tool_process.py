from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Callable, Dict, Optional, Sequence, Union

Command = Union[str, Sequence[object]]
ErrorType = Callable[[str], Exception]


def _command(command: Command) -> Union[str, list]:
    return command if isinstance(command, str) else [str(part) for part in command]


def command_text(command: Command) -> str:
    return command if isinstance(command, str) else " ".join(str(part) for part in command)


def failure_text(what: str, code: int, cwd: Optional[Path] = None) -> str:
    return "{} returned {}{}".format(what, code, "" if cwd is None else " in {}".format(cwd))


def exit_code(command: Command, cwd: Optional[Path] = None, env: Optional[Dict[str, str]] = None) -> int:
    return subprocess.run(_command(command), cwd=None if cwd is None else str(cwd), env=env,
                          check=False).returncode


def run_or_raise(command: Command, error: ErrorType, what: Optional[str] = None,
                 cwd: Optional[Path] = None, env: Optional[Dict[str, str]] = None) -> None:
    code = exit_code(command, cwd, env)
    if code != 0:
        raise error(failure_text(what or command_text(command), code, cwd))


def output_or_raise(command: Command, error: ErrorType, what: Optional[str] = None,
                    env: Optional[Dict[str, str]] = None, encoding: Optional[str] = "utf-8") -> Union[str, bytes]:
    result = subprocess.run(_command(command), env=env, capture_output=True, check=False)
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace").strip()
        raise error("{}{}".format(failure_text(what or command_text(command), result.returncode),
                                  ": " + detail if detail else ""))
    return result.stdout if encoding is None else result.stdout.decode(encoding, errors="replace")


def prepend_path(env: Dict[str, str], *directories: Path) -> Dict[str, str]:
    result = dict(env)
    result["PATH"] = os.pathsep.join([str(d) for d in directories] + [result.get("PATH", "")])
    return result
