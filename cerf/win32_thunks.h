#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <map>
#include <functional>
#include "mem.h"
#include "pe_loader.h"

/* Magic address range for thunk entries.
   When ARM code branches to an address in this range, we intercept it. */
#define THUNK_BASE   0xF0000000
#define THUNK_STRIDE 4

struct ThunkEntry {
    std::string dll_name;
    std::string func_name;
    uint16_t    ordinal;
    bool        by_ordinal;
    uint32_t    thunk_addr;    /* Address in thunk region */
};

/* Helper to read a wide string from emulated memory */
std::wstring ReadWStringFromEmu(EmulatedMemory& mem, uint32_t addr);

/* Helper to read a narrow string from emulated memory */
std::string ReadStringFromEmu(EmulatedMemory& mem, uint32_t addr);

class Win32Thunks {
public:
    Win32Thunks(EmulatedMemory& mem);

    /* Install thunks for all imports in a loaded PE.
       Replaces IAT entries with thunk addresses. */
    void InstallThunks(PEInfo& info);

    /* Handle a thunk call. Called when ARM CPU branches to a thunk address.
       Returns true if the address was a thunk and was handled.
       regs[0..15] = R0-R15 */
    bool HandleThunk(uint32_t addr, uint32_t* regs, EmulatedMemory& mem);

    /* Set the emulated HINSTANCE for the WinCE app */
    void SetHInstance(uint32_t hinst) { emu_hinstance = hinst; }
    void SetExePath(const std::wstring& path) { exe_path = path; }
    void SetExeDir(const std::string& dir) { exe_dir = dir; }

    /* Execute a callback from native code back into ARM emulator.
       Args: (arm_addr, args_array, num_args) -> return value */
    typedef std::function<uint32_t(uint32_t addr, uint32_t* args, int nargs)> CallbackExecutor;
    CallbackExecutor callback_executor;

    /* Store ARM WndProc addresses per class name */
    std::map<std::wstring, uint32_t> arm_wndprocs;
    /* Map HWND -> ARM WndProc */
    static std::map<HWND, uint32_t> hwnd_wndproc_map;
    /* Map timer ID -> ARM TIMERPROC callback address */
    static std::map<UINT_PTR, uint32_t> arm_timer_callbacks;
    /* Map HWND -> ARM DlgProc callback address */
    static std::map<HWND, uint32_t> hwnd_dlgproc_map;
    /* Modal dialog result for EndDialog */
    static INT_PTR modal_dlg_result;
    static bool modal_dlg_ended;
    static Win32Thunks* s_instance;  /* For static WndProc callback */

    static LRESULT CALLBACK EmuWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static INT_PTR CALLBACK EmuDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

private:
    EmulatedMemory& mem;
    std::map<uint32_t, ThunkEntry> thunks;   /* thunk_addr -> entry */
    uint32_t next_thunk_addr;

    uint32_t emu_hinstance;
    std::wstring exe_path;
    std::string exe_dir;  /* Directory containing the exe */

    /* Loaded ARM DLLs */
    struct LoadedDll {
        std::string path;
        uint32_t base_addr;
        PEInfo pe_info;
        HMODULE native_rsrc_handle; /* Native load for resource access */
    };
    std::map<std::wstring, LoadedDll> loaded_dlls; /* lowercase name -> info */

    /* Resource handle mapping (fake emu handle -> resource data location) */
    struct EmuRsrc {
        uint32_t data_rva;  /* RVA of resource data in the PE image */
        uint32_t data_size; /* Size of resource data */
        uint32_t module_base; /* Base address of the module */
    };
    std::map<uint32_t, EmuRsrc> rsrc_map;
    uint32_t next_rsrc_handle = 0xE0000000;

    /* Find a resource in an ARM PE loaded in emulated memory */
    uint32_t FindResourceInPE(uint32_t module_base, uint32_t rsrc_rva, uint32_t rsrc_size,
                              uint32_t type_id, uint32_t name_id,
                              uint32_t& out_data_rva, uint32_t& out_data_size);

    /* Ordinal to function name mapping */
    static std::map<uint16_t, std::string> ordinal_map;
    static void InitOrdinalMap();
    std::string ResolveOrdinal(uint16_t ordinal);

    /* Allocate a thunk address for a function */
    uint32_t AllocThunk(const std::string& dll, const std::string& func, uint16_t ordinal, bool by_ordinal);

    /* Execute a specific thunked Win32 API call */
    bool ExecuteThunk(const ThunkEntry& entry, uint32_t* regs, EmulatedMemory& mem);

    /* Read stack arguments (beyond R0-R3) */
    uint32_t ReadStackArg(uint32_t* regs, EmulatedMemory& mem, int index);

    /* Get a native HMODULE for resource access from an emulated module handle */
    HMODULE GetNativeModuleForResources(uint32_t emu_handle);

    /* Category dispatch methods (each in its own .cpp file) */
    bool ExecuteMemoryThunk(const std::string& func, uint32_t* regs, EmulatedMemory& mem);
    bool ExecuteStringThunk(const std::string& func, uint32_t* regs, EmulatedMemory& mem);
    bool ExecuteGdiThunk(const std::string& func, uint32_t* regs, EmulatedMemory& mem);
    bool ExecuteWindowThunk(const std::string& func, uint32_t* regs, EmulatedMemory& mem);
    bool ExecuteSystemThunk(const std::string& func, uint32_t* regs, EmulatedMemory& mem);

    /* Individual API thunk implementations */
    bool Thunk_GetModuleHandleW(uint32_t* regs, EmulatedMemory& mem);
    bool Thunk_GetModuleFileNameW(uint32_t* regs, EmulatedMemory& mem);
    bool Thunk_LoadLibraryW(uint32_t* regs, EmulatedMemory& mem);
    bool Thunk_GetProcAddressW(uint32_t* regs, EmulatedMemory& mem);
    bool Thunk_GetCommandLineW(uint32_t* regs, EmulatedMemory& mem);
    bool Thunk_ExitProcess(uint32_t* regs, EmulatedMemory& mem);
    bool Thunk_ExitThread(uint32_t* regs, EmulatedMemory& mem);
};
