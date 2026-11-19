import argparse
import json
import os

from cerf_automation import Cerf

parser = argparse.ArgumentParser(prog="python -m cerf_automation.examples.compact_flash")
parser.add_argument("endpoint")
parser.add_argument("socket", help="object path of a socket that accepts the cf type, ids joined by /")
parser.add_argument("image", help="output image file")
parser.add_argument("files", nargs="+")
parser.add_argument("--size-mb", type=int, default=32)
args = parser.parse_args()

cerf = Cerf.connect(endpoint=args.endpoint, wait=10)
cerf.subscribe("object")
result = cerf.socket.insert(path=args.socket.split("/"), type="cf", command="generate_fat32",
                            answers={"compact_flash_documents": [os.path.abspath(f) for f in args.files],
                                     "compact_flash_size_mb": args.size_mb,
                                     "compact_flash_output_image": os.path.abspath(args.image)})
print("answered:", result["answered"])
event = cerf.wait_event("object", lambda e: e["event"] in ("inserted", "failed"), timeout=60)
print(event["event"], json.dumps(event["object"]["state"]["inserted"] if event["event"] == "inserted" else event))
cerf.close()
