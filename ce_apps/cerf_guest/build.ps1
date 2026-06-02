Set-Location $PSScriptRoot
& "$PSScriptRoot/../../tools/build_ce_app.ps1" `
    -Type dll -Target cerf_guest.dll `
    -Sources main.cpp,cerf_ddgpe.cpp,cerf_ddhal.cpp,cerf_gradient.cpp `
    -Entry DllEntryPoint `
    -ExtraIncludes "$PSScriptRoot/shim","$PSScriptRoot/../../references/WindowsCE-Build-Tools/ce6-oak/INC","$PSScriptRoot/../../references/WindowsCE-Build-Tools/ce42-standard/Include/Armv4i" `
    -ExtraLibPaths "$PSScriptRoot/../../references/WindowsCE-Build-Tools/ce6-oak/Lib/Armv4i/retail" `
    -Libs coredll,ddgpe,gpe_lib,emul,emulrotate,genblt,genblt_cpu,ctbltstub,aablt,drvalphablendstub,drvgradfillstub `
    -ForcedInclude "ce6_shim.h" `
    -LinkExtras "/MERGE:.rdata=.text"
