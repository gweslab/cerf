# 1-Calc.exe Known Issues

## Status: Fixed

## Setup
- App location: `devices/wince5/fs/Optional Apps/1-Calc/1-Calc.exe`
- Skins location: `devices/wince5/fs/Optional Apps/1-Calc/Skins/` (NOT in `\Windows\Skins\`)
- On real CE devices, 1-Calc reads skins from its own working directory, not from `\Windows\`
- Run command: `cerf.exe --flush-outputs "devices/wince5/fs/Optional Apps/1-Calc/1-Calc.exe"`
- Reference screenshot: `known_issues/1-Calc/real_ce_device.png`

## Fixes Applied

### GetModuleFileNameW path fix
- **Problem**: GetModuleFileNameW always returned `\Windows\<filename>`, causing skin lookups at `\Windows\Skins\` which is wrong for apps installed outside `\Windows\`
- **Fix**: Changed GetModuleFileNameW to resolve the actual exe path via GetFullPathNameW and MapHostToWinCE, so the app gets its real installation directory
- **File**: `cerf/thunks/coredll/module.cpp`

### Missing math ordinals
- Implemented: acos(989), asin(990), atan(991), cos(1004), cosh(1005), exp(1009), log(1033), log10(1034), sin(1058), sinh(1059), tan(1075), tanh(1076), ceil(999), fmod(1014), atan2(992), modf(1048), _gcvt(1022)
- **File**: `cerf/thunks/coredll/crt.cpp`

### sprintf implementation (ordinal 719)
- Full format string processing implementation
- **File**: `cerf/thunks/coredll/string.cpp`

### MaskBlt (ordinal 904)
- Full parameter marshalling for 12-parameter function
- **File**: `cerf/thunks/coredll/gdi_draw.cpp`

### DeferWindowPos family (1157-1159)
- BeginDeferWindowPos, DeferWindowPos, EndDeferWindowPos
- **File**: `cerf/thunks/coredll/window.cpp`

### Ordinal conflict fixes
- Ordinal 1058 was mapped to both sprintf and sin; fixed to sin (sprintf is 719)
- Ordinal 993 was mapped to ceil; fixed (993 is atoi, ceil is 999)

### swscanf implementation (ordinal 1098)
- **Problem**: swscanf was aliased to _snwprintf handler (a printf function, not scanf!)
- **Fix**: Implemented full swscanf parser supporting %d, %u, %x, %s, %c, %f, %ld, %lu, %lx
- **File**: `cerf/thunks/coredll/string.cpp`

### wcstok implementation (ordinal 77) — Root cause of white buttons
- **Problem**: wcstok was stubbed to always return NULL. The app's ini parser uses wcstok to tokenize color values from Button.ini (e.g., "248,248,248" split by comma). With wcstok returning NULL, all parsed color values were 0, producing white gradient buttons.
- **Fix**: Implemented full wcstok with static state (2-arg WinCE signature like POSIX strtok), supporting delimiter skipping, token extraction, and null-termination of delimiters.
- **File**: `cerf/thunks/coredll/string.cpp`

### wcspbrk implementation
- **Problem**: wcspbrk was aliased to the stubbed wcstok. wcspbrk is a different function (find first char from set in string).
- **Fix**: Implemented proper wcspbrk that searches for first occurrence of any character from the charset.
- **File**: `cerf/thunks/coredll/string.cpp`
