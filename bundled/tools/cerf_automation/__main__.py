from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any, List

from .client import Cerf, CerfError


def value(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return text


def params(pairs: List[str]) -> dict:
    out = {}
    for pair in pairs:
        key, sep, raw = pair.partition("=")
        if not sep:
            raise SystemExit("parameter {!r} is not key=value".format(pair))
        out[key] = value(raw)
    return out


def connect(args: argparse.Namespace) -> Cerf:
    return Cerf.connect(endpoint=args.endpoint, device=args.device, cerf=args.cerf, wait=args.wait)


def show(result: Any) -> None:
    print(json.dumps(result, indent=2))


def main(argv: List[str]) -> int:
    parser = argparse.ArgumentParser(prog="python -m cerf_automation",
                                     description="Drive a CE Runtime Foundation instance started with --automation.")
    target = parser.add_mutually_exclusive_group()
    target.add_argument("--endpoint", help="endpoint name or address of the instance")
    target.add_argument("--device", help="device whose running instance to use")
    parser.add_argument("--cerf", help="CE Runtime Foundation executable or its folder (default: CERF_EXE, then this install)")
    parser.add_argument("--wait", type=float, default=0.0, help="seconds to wait for the endpoint")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("running", help="list running instances that have an endpoint")
    commands.add_parser("describe", help="list the methods and event topics of the instance")
    call = commands.add_parser("call", help="call one method, for example: call pointer.press x=10 y=20")
    call.add_argument("method")
    call.add_argument("params", nargs="*", help="key=value; a value is JSON when it parses as JSON")
    watch = commands.add_parser("watch", help="print the events of topics")
    watch.add_argument("topics", nargs="+")
    watch.add_argument("--seconds", type=float, default=None, help="stop after this many seconds")
    args = parser.parse_args(argv)

    if args.command == "running":
        show(Cerf.running(args.cerf))
        return 0
    if args.endpoint is None and args.device is None:
        parser.error("give --endpoint or --device")
    cerf = connect(args)
    try:
        if args.command == "describe":
            show({"methods": list(cerf.methods.values()), "topics": list(cerf.topics.values())})
        elif args.command == "call":
            show(cerf.call(args.method, **params(args.params)))
        else:
            show(cerf.subscribe(*args.topics))
            deadline = None if args.seconds is None else time.monotonic() + args.seconds
            while deadline is None or time.monotonic() < deadline:
                left = None if deadline is None else max(0.0, deadline - time.monotonic())
                event = cerf.next_event(left)
                if event is not None:
                    print(json.dumps({"topic": event[0], "data": event[1]}), flush=True)
    except CerfError as error:
        print("error: " + str(error), file=sys.stderr)
        return 1
    finally:
        cerf.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
