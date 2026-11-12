import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "tools"))
from build_ce_app import run_app

COMMON = dict(type="exe", target="cerf_gdiprobe.exe", entry="WinMain", libs=["coredll"],
              coredll_def=str(HERE.parent / "cerf_guest" / "coredll_ce2.def"))

SOURCES = ["main.cpp", "probe_gdi.cpp", "probe_overhang.cpp", "probe_wide.cpp"]

VARIANTS = [
    dict(COMMON, arch="arm", obj_dir="obj_arm", sources=SOURCES,
         wce_version="211", subsystem_version="2.11"),
    dict(COMMON, arch="mips", mips_isa="mips1", obj_dir="obj_mips1",
         sources=SOURCES + [str(HERE.parent / "cerf_guest" / "cerf_ce2_crt.cpp")],
         wce_version="100", subsystem_version="2.00"),
]

if __name__ == "__main__":
    sys.exit(run_app(HERE, VARIANTS))
