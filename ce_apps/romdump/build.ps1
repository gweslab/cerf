Set-Location $PSScriptRoot
$build   = "$PSScriptRoot/../../tools/build_ce_app.ps1"
$src     = "main.cpp,step_preset.cpp,step_config.cpp,step_dump.cpp,dump.cpp"
$ce2def  = "$PSScriptRoot/../cerf_guest/coredll_ce2.def"
$def     = "$PSScriptRoot/../cerf_guest/coredll_byname.def"
$srcs      = $src -split ","
$srcs_ce2  = $srcs + "$PSScriptRoot/../cerf_guest/cerf_ce2_crt.cpp"
$srcs_sh3  = $srcs_ce2 + "$PSScriptRoot/../cerf_guest/cerf_rt_sh.cpp"

& $build -Type exe -Target romdump.exe -Arch arm -ObjDir obj_arm `
    -Sources $srcs -Entry WinMain -Libs coredll -Rc romdump.rc `
    -CoreDllDef $ce2def -WceVersion "100" -SubsystemVersion "2.00"

& $build -Type exe -Target romdump.exe -Arch mips -MipsIsa mips1 -ObjDir obj_mips1 `
    -Sources $srcs_ce2 -Entry WinMain -Libs coredll -Rc romdump.rc `
    -CoreDllDef $ce2def -WceVersion "100" -SubsystemVersion "1.00"

& $build -Type exe -Target romdump.exe -Arch sh3 -ObjDir obj_sh3 `
    -Sources $srcs_sh3 -Entry WinMain -Libs coredll -Rc romdump.rc `
    -CoreDllDef $ce2def -WceVersion "100" -SubsystemVersion "1.00"

& $build -Type exe -Target romdump.exe -Arch mips -MipsIsa mips4 -ObjDir obj_mips4 `
    -Sources $srcs -Entry WinMain -Libs coredll -Rc romdump.rc `
    -CoreDllDef $def
