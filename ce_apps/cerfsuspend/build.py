import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "tools"))
from build_ce_app import run_app

COMMON = dict(type="exe", target="cerfsuspend.exe", sources=["main.c"], entry="WinMain",
              libs=["coredll"], coredll_def=str(HERE.parent / "cerf_guest" / "coredll_ce2.def"))

VARIANTS = [
    dict(COMMON, arch="arm", obj_dir="obj_arm", wce_version="211", subsystem_version="2.11"),
    dict(COMMON, arch="mips", mips_isa="mips1", obj_dir="obj_mips1", wce_version="100",
         subsystem_version="2.00"),
]

if __name__ == "__main__":
    sys.exit(run_app(HERE, VARIANTS))
