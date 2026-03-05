# Multi-Process Support

## Current State: In-Process Execution
ShellExecuteEx loads child ARM PEs into the **same cerf instance** using PELoader::Load,
installs thunks, and calls WinMain via callback_executor. This matches real WinCE where
all processes share registry, window handles, and message broadcasts.

- Child apps run synchronously (modal) within the parent's callback executor
- Shared: emulated memory, registry, HWNDs, WM_SETTINGCHANGE broadcasts
- Example: explorer.exe → right-click Properties → ctlpnl.exe runs in-process

## Future: Concurrent Multi-Process
For apps that need to run concurrently (non-modal):
- Thread-based scheduling within a single cerf instance
- Process table tracking per-process state (hInstance, loaded DLLs)
- Preemptive or cooperative context switching between ARM instruction streams
