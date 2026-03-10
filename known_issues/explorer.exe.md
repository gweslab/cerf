# Explorer.exe Status

## Working
- Desktop shell loads and displays icons (My Device, Recycle Bin, SampleText)
- Taskbar with Start button and clock
- Double-click / Enter on desktop icons opens Explore window
- **Explore window navigation**: Navigate2 successfully navigates to `\` (root)
  - File browser menus (File, Edit, View, Go, Favorites) display correctly
  - Shell view created, items populated (directories listed from VFS root)
  - Folder icons render correctly (iImage callbacks work)
  - shdocvw COM initialization chain: SetOwner QI(IBrowserService/IShellBrowser/IServiceProvider) all succeed

## Known Issues

### OLE Infinite Loop (CDllCache::CleanUpLocalServersForApartment)
- **Status**: OPEN — root cause is pseudo-threading
- **Symptom**: App hangs/crashes when opening Explore window. Watchdog detects infinite loop at PC=0x10064D10
- **Root cause**: `CDllCache::CleanUpLocalServersForApartment` (ole32.dll, base 0x10000000, func at 0x10064CB8) iterates `_pClassEntries` linked list. The list becomes circular because pseudo-threading runs multiple OLE apartment initializations on the same real OS thread, corrupting apartment data structures.
- **Why thunk-level fix fails**: ARM code calls ARM ole32.dll's `CoInitializeEx` directly via IAT (not through our coredll thunk), so our pseudo-thread skip in misc.cpp is ineffective.
- **Potential fix approaches**:
  1. **ARM memory patch**: Write `BX LR` (0xE12FFF1E) at 0x10064CB8 after DLLs load to make it a no-op
  2. **Real threading** (preferred): Give each CreateThread call its own real OS thread with independent CPU state and TLS, eliminating apartment corruption entirely
- **Key IDA analysis**:
  - `CDllCache::CleanUpLocalServersForApartment` at 0x10064CB8: iterates _pClassEntries linked list
  - `COleTls::COleTls` at 0x1001E890: checks GetCurrentProcessId vs GetOwnerProcess, accesses TLS slot 4
  - `CoInitializeEx` at 0x1001D2B4: increments cComInits, calls wCoInitializeEx on first call
  - `wCoInitializeEx` at 0x1001D528: ProcessInitialize, STA/MTA mode setup
  - `InitMainThreadWnd` at 0x10066360: creates OleMainThreadWndClass window
- **Explorer call chain**: `HandleNewWindow2` → `CreateThread(NewWindow)` → `CoInitializeEx` → `CMainWnd::Create` → `CBrowseObj::CreateBrowser` → `CoCreateInstance(WebBrowser)` → OLE apartment init → apartment corruption → infinite loop on CoUninitialize

### Item Positioning in Explore ListView
- **Status**: OPEN
- 23 items inserted but most clustered at wrong positions (only last 2 visible)
- Root cause: ARM commctrl defers item positioning via PostMessage(WM_USER). These messages
  get dispatched while the ListView is still at its initial 320x240 size. Items get positioned
  for that small size, then the window resizes to full screen but items keep old positions.

### Missing Title Bar
- Explore window appears without title bar / caption
- May be related to layout translation (WinCE thin frames vs desktop thick frames)

### Missing Toolbar / Address Bar
- Small empty control visible in top-left of Explore window
- Toolbar creation may be failing or toolbar is at wrong position

### X Button Infinite Loop (calc.exe regression)
- Do NOT click X button on calc.exe — causes infinite loop

### CAnimThread WM_TIMER Flood (FIXED)
- Animation thread's SetTimer created WM_TIMER flood preventing pseudo-thread GetMessageW timeout
- Fixed by not resetting `empty_waits` counter on WM_TIMER messages in message.cpp
