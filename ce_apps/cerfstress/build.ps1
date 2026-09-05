Set-Location $PSScriptRoot
$build  = "$PSScriptRoot/../../tools/build_ce_app.ps1"
$ce2def = "$PSScriptRoot/../cerf_guest/coredll_ce2.def"

& $build -Type exe -Target cerfstress.exe -Arch arm -ObjDir obj_arm `
    -Sources main.cpp -Entry WinMain -Libs coredll `
    -CoreDllDef $ce2def -WceVersion "211" -SubsystemVersion "2.11"

& $build -Type exe -Target cerfstress.exe -Arch arm_thumb -ObjDir obj_thumb `
    -Sources main.cpp -Entry WinMain -Libs coredll `
    -CoreDllDef $ce2def -WceVersion "211" -SubsystemVersion "2.11"
