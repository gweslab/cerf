import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "tools"))
from build_ce_app import run_app

COMMON = dict(type="dll", target="cerf_guest_stub.dll",
              sources=["main.cpp", "../cerf_guest/cerf_virt_base.cpp",
                       "../cerf_guest/cerf_regs_map.cpp", "../cerf_guest/cerf_debug_log.cpp"],
              entry="DllEntryPoint",
              extra_includes=[str(HERE.parent / "cerf_guest"),
                              str(HERE.parent / "cerf_guest" / "include")],
              libs=["coredll"], coredll_def=str(HERE.parent / "cerf_guest" / "coredll_byname.def"),
              link_extras=["/MERGE:.rdata=.text"])

VARIANTS = [
    dict(COMMON, arch="arm", obj_dir="obj_arm"),
    dict(COMMON, arch="arm_thumb", obj_dir="obj_thumb", def_file="cerf_guest_stub.def"),
    dict(COMMON, arch="mips", mips_isa="mips4", obj_dir="obj_mips4",
         def_file="cerf_guest_stub.def"),
    dict(COMMON, arch="mips", mips_isa="mips1", obj_dir="obj_mips1",
         def_file="cerf_guest_stub.def"),
    dict(COMMON, arch="sh3", obj_dir="obj_sh3", def_file="cerf_guest_stub.def"),
]

if __name__ == "__main__":
    sys.exit(run_app(HERE, VARIANTS))
