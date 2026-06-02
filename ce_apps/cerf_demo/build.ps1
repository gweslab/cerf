Set-Location $PSScriptRoot
& "$PSScriptRoot/../../tools/build_ce_app.ps1" `
    -Type exe -Target CerfDemo.exe `
    -Sources main.c,desktop.c -Entry WinMain `
    -ExtraIncludes "$PSScriptRoot/../../references/WindowsCE-Build-Tools/ce5-standard/Include/Armv4i" `
    -ExtraLibPaths "$PSScriptRoot/../../references/WindowsCE-Build-Tools/ce5-standard/Lib/Armv4i" `
    -Libs coredll `
    -LinkExtras "/FIXED:NO"

