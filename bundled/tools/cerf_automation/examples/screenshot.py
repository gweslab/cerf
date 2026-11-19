import argparse
import os

from cerf_automation import Cerf

parser = argparse.ArgumentParser(prog="python -m cerf_automation.examples.screenshot")
parser.add_argument("device")
parser.add_argument("png")
args = parser.parse_args()

with Cerf.spawn(args.device, args=["--no-focus"]) as cerf:
    cerf.wait_for(lambda: cerf.status()["has_frame"], timeout=120)
    frame = cerf.frame()
    frame.save_png(os.path.abspath(args.png))
    print(cerf.hello()["board_name"], frame.width, "x", frame.height)
