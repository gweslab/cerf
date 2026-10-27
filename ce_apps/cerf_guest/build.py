import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent.parent / "tools"))
from build_ce_app import run_app

SOURCES = ["main.cpp", "cerf_virt_base.cpp", "cerf_regs_map.cpp", "cerf_debug_log.cpp",
           "cerf_ce2_crt.cpp", "cerf_rt_div_arm.cpp",
           "cerf_eng_callbacks.cpp",
           "cerf_gpe.cpp", "cerf_ddi_pdev.cpp", "cerf_ddi_blt.cpp", "cerf_ddi_device.cpp",
           "cerf_ddi_stroke.cpp", "cerf_ddi_fill.cpp",
           "cerf_ddgpe.cpp", "cerf_ddgpe_blt.cpp", "cerf_ddgpe_band.cpp",
           "cerf_ddgpe_alias.cpp",
           "cerf_ddgpe_line.cpp",
           "cerf_ddgpe_vidmem.cpp", "cerf_ddgpe_ddhal.cpp",
           "cerf_ddhal.cpp", "cerf_ddhal_ce5.cpp",
           "cerf_dma_arena.cpp",
           "cerf_gradient.cpp",
           "cerf_gwes_ready.cpp",
           "cerf_input_pump.cpp", "cerf_service_pump.cpp",
           "cerf_resize_pump.cpp", "cerf_task_manager_pump.cpp",
           "cerf_calib_warning_pump.cpp", "cerf_cleartype_pump.cpp",
           "cerf_shell_watch.cpp", "cerf_init_table.cpp",
           "cerf_window_owner.cpp",
           "cerf_process_spawn.cpp", "cerf_autorun.cpp",
           "cerf_toolhelp.cpp", "cerf_sync2_shell_replace.cpp",
           "cerf_power.cpp",
           "cerf_cursor.cpp",
           "cerf_getversionexw.cpp",
           "cerf_registry_customizations.cpp", "cerf_allow_unsigned_apps.cpp",
           "cerf_coredll_proc.cpp",
           "cerf_ndis.cpp", "cerf_ndis_slot.cpp", "cerf_ndis_miniport.cpp",
           "cerf_ndis_install.cpp",
           "cerf_ndis_packet_rx.cpp", "cerf_ndis_oids.cpp",
           "cerf_driver_in_driver.cpp", "cerf_fs_afs.cpp", "cerf_fs_transport.cpp",
           "cerf_fs_vol.cpp", "cerf_fs_file.cpp", "cerf_fs_find.cpp", "cerf_fs_notify.cpp"]

LOCAL_CRT = ["??2@YAPAXI@Z", "??3@YAXPAX@Z", "??_U@YAPAXI@Z", "??_V@YAXPAX@Z",
             "_purecall", "memcpy", "memmove", "memset",
             "__rt_sdiv", "__rt_udiv", "__ll_div", "__ll_lshift"]

COMMON = dict(type="dll", target="cerf_guest.dll", sources=SOURCES, entry="DllEntryPoint",
              extra_includes=[str(HERE / "include")], libs=["coredll"],
              coredll_def_local=LOCAL_CRT, forced_include=["cerf_debug_log.h"],
              link_extras=["/MERGE:.rdata=.text"])
BYNAME = str(HERE / "coredll_byname.def")

VARIANTS = [
    dict(COMMON, arch="arm", obj_dir="obj_arm", coredll_def=BYNAME),
    dict(COMMON, arch="arm_thumb", obj_dir="obj_thumb", def_file="cerf_guest.def",
         coredll_def=BYNAME),
    dict(COMMON, arch="mips", mips_isa="mips4", obj_dir="obj_mips4", def_file="cerf_guest.def",
         coredll_def=BYNAME),
    dict(COMMON, arch="mips", mips_isa="mips1", obj_dir="obj_mips1", def_file="cerf_guest.def",
         coredll_def=str(HERE / "coredll_ce2.def")),
]

if __name__ == "__main__":
    sys.exit(run_app(HERE, VARIANTS))
