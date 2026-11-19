import argparse

from cerf_automation import Cerf

parser = argparse.ArgumentParser(prog="python -m cerf_automation.examples.type_text")
parser.add_argument("endpoint")
parser.add_argument("x", type=int)
parser.add_argument("y", type=int)
parser.add_argument("text")
args = parser.parse_args()

cerf = Cerf.connect(endpoint=args.endpoint, wait=10)
before = cerf.frame()
cerf.tap(args.x, args.y)
cerf.type_text(args.text)
cerf.wait_for(lambda: cerf.frame() != before, timeout=10)
print("changed pixels:", before.changed_pixels(cerf.frame()))
cerf.close()
