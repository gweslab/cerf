# cplmain.cpl — Control Panel Applets (System Properties, etc.)

## RESOLVED: Tab switching crash/hang in System Properties

**Status**: RESOLVED

**Symptom**: Right-click My Device → Properties → click through tabs (General, Memory, Device Name, Copyrights). After a few tab switches the app would crash or hang.

**Root cause (two issues)**:

1. **SWBKPT (0xE6000010) misinterpreted as LDR/STR**: WinCE uses ARM undefined instruction space (`bits [27:25]=011, bit[4]=1`) for `__debugbreak()`. The ARM decoder matched `bits [27:26]=01` first and decoded it as `STR R0,[R0],-R0`, corrupting R0 and writing to arbitrary memory. Over multiple tab switches this accumulated damage caused freezes.

2. **Null m_pfnDlg function pointer**: `CplPageProc` (shared dialog proc at 0x10009300 in IDA) dispatches to per-page callbacks via `CRunningTab::m_pfnDlg` (offset +8). Some tab configurations left this NULL. The callback executor would then run at PC=0, executing 4KB of zeroed memory (`ANDEQ R0,R0,R0` = NOP) until hitting unmapped memory.

**Fix**:
- `cerf/cpu/arm_insn.cpp`: Added undefined instruction check `(insn & 0x0E000010) == 0x06000010` before LDR/STR handler — treats as NOP.
- `cerf/main.cpp`: Added null function pointer guard in `callback_executor` — if `PC < 0x1000` during nested callback, abort and return 0.

**Key structures** (from IDA reverse engineering of cplmain.cpl):
- `CRunningTab` (44 bytes): +0=m_pTabData, +4=m_psp, +8=m_pfnDlg, +12=m_iApplet, +16=m_iTab, +20=m_hwndSavedFocus, +24=m_hwndSheet, +28=m_hfontBold
- `PROPSHEETPAGEW` (WinCE, 40 bytes): +24=pfnDlgProc, +28=lParam (→CRunningTab*)
- Page DlgProcs: SystemDlgProc (General), MemoryDlgProc (Memory), SystemIdentDlgProc (Device Name), CopyrightsDlgProc (Copyrights)

## OPEN: Negative memory value on General tab

**Status**: OPEN

**Symptom**: General tab shows "-486438807 KB RAM" instead of correct memory amount.

**Notes**: `GlobalMemoryStatus` thunk returns correct 2047 MB. The negative value likely comes from a different code path or struct field mismatch in how the ARM code reads the result.

## OPEN: Ghost taskbar buttons

**Status**: OPEN

**Symptom**: After switching tabs multiple times, duplicate/ghost taskbar entries appear flooding the taskbar. Likely related to property sheet page creation creating spurious top-level windows.
