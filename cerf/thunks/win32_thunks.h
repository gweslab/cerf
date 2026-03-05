#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <functional>
#include <algorithm>
#include <cstring>
#include "../cpu/mem.h"
#include "../loader/pe_loader.h"

/* Thunked DLL registry — single source of truth for all system DLLs we emulate.
   To add a new thunked DLL: add one entry here, then create Register*Handlers(). */
struct ThunkedDllInfo {
    const char* name;          /* lowercase key (e.g. "coredll") */
    uint32_t    fake_handle;   /* returned by GetModuleHandle/LoadLibrary */
};

inline const ThunkedDllInfo thunked_dlls[] = {
    { "coredll",   0xCE000000 },
};

/* Look up a thunked DLL by name (narrow, case-insensitive, substring match) */
inline const ThunkedDllInfo* FindThunkedDll(const std::string& dll_name) {
    std::string lower = dll_name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (const auto& dll : thunked_dlls)
        if (lower.find(dll.name) != std::string::npos) return &dll;
    return nullptr;
}

/* Wide string version for LoadLibraryW / GetModuleHandleW */
inline const ThunkedDllInfo* FindThunkedDllW(const std::wstring& dll_name) {
    std::wstring lower = dll_name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
    for (const auto& dll : thunked_dlls) {
        std::wstring wide_name(dll.name, dll.name + strlen(dll.name));
        if (lower.find(wide_name) != std::wstring::npos) return &dll;
    }
    return nullptr;
}

/* Magic address range for thunk entries.
   When ARM code branches to an address in this range, we intercept it.
   NOTE: 0xF000xxxx is reserved for WinCE kernel trap-based API calls. */
#define THUNK_BASE   0xFE000000
#define THUNK_STRIDE 4

/* Emulated WinCE screen resolution.
   ARM apps see this as the device screen size via GetSystemMetrics
   and SystemParametersInfoW(SPI_GETWORKAREA). */
#define WINCE_SCREEN_WIDTH   800
#define WINCE_SCREEN_HEIGHT  600

/* WinCE trap-based API call range.
   WinCE apps may call APIs via trap addresses descending from 0xF0010000.
   API index = (0xF0010000 - addr) / 4 */
#define WINCE_TRAP_BASE  0xF0000000
#define WINCE_TRAP_TOP   0xF0010000

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

    /* Call DllMain for all loaded ARM DLLs. Must be called after callback_executor is set up. */
    void CallDllEntryPoints();

    /* Handle a thunk call. Called when ARM CPU branches to a thunk address.
       Returns true if the address was a thunk and was handled.
       regs[0..15] = R0-R15 */
    bool HandleThunk(uint32_t addr, uint32_t* regs, EmulatedMemory& mem);

    /* Set the emulated HINSTANCE for the WinCE app */
    void SetHInstance(uint32_t hinst) { emu_hinstance = hinst; }
    void SetExePath(const std::wstring& path) { exe_path = path; }
    void SetExeDir(const std::string& dir) { exe_dir = dir; }
    void SetWinceSysDir(const std::string& dir) { wince_sys_dir = dir; }

    /* Virtual filesystem initialization — reads cerf.ini, sets device paths.
       If device_override is non-empty, it overrides the cerf.ini setting. */
    void InitVFS(const std::string& device_override = "");

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
    /* Stashed ARM DlgProc for CreateDialogIndirectParamW: WM_INITDIALOG is sent
       during the API call before it returns, so hwnd_dlgproc_map isn't populated yet. */
    static uint32_t pending_arm_dlgproc;
    /* HWNDs created with WS_EX_CAPTIONOKBTN (0x80000000).  Style is stripped
       before native CreateWindowEx, but tracked here so WM_CLOSE is converted
       to WM_COMMAND(IDOK) and GetWindowLongW reports the original style. */
    static std::set<HWND> captionok_hwnds;
    /* Modal dialog result for EndDialog */
    static INT_PTR modal_dlg_result;
    static bool modal_dlg_ended;
    static Win32Thunks* s_instance;  /* For static WndProc callback */
    /* setjmp buffer stack for RaiseException recovery (poor man's SEH) */
    std::vector<uint32_t> setjmp_stack;

    static LRESULT CALLBACK EmuWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static INT_PTR CALLBACK EmuDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK MenuBarWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    /* Install/remove the WS_EX_CAPTIONOKBTN title bar button subclass on a window */
    static void InstallCaptionOk(HWND hwnd);
    static void RemoveCaptionOk(HWND hwnd);
private:
    static LRESULT CALLBACK CaptionOkSubclassProc(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);

private:
    EmulatedMemory& mem;
    std::map<uint32_t, ThunkEntry> thunks;   /* thunk_addr -> entry */
    uint32_t next_thunk_addr;

    uint32_t emu_hinstance;
    std::wstring exe_path;
    std::string exe_dir;  /* Directory containing the exe */
    std::string wince_sys_dir;  /* WinCE system DLL directory (for ARM DLLs like commctrl.dll) */

    /* WinCE system font (from HKLM\System\GDI\SYSFNT registry key).
       Used to remap "System" font requests to the device's actual font. */
    std::wstring wce_sysfont_name = L"Tahoma";  /* default fallback */
    LONG wce_sysfont_height = -12;
    LONG wce_sysfont_weight = FW_NORMAL;
    void InitWceSysFont();

    /* Virtual filesystem device paths */
    std::string cerf_dir;        /* Directory containing cerf.exe */
    std::string device_name;     /* Active device name (e.g. "wince5") */
    std::string device_fs_root;  /* <cerf_dir>/devices/<device>/fs/ */
    std::string device_dir;      /* <cerf_dir>/devices/<device>/ */

    /* Loaded ARM DLLs */
    struct LoadedDll {
        std::string path;
        uint32_t base_addr;
        PEInfo pe_info;
        HMODULE native_rsrc_handle; /* Native load for resource access */
    };
    std::map<std::wstring, LoadedDll> loaded_dlls; /* lowercase name -> info */
    LoadedDll* LoadArmDll(const std::string& dll_name); /* Find/load ARM DLL */

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

    /* Pending DLL entry points to call after callback_executor is set up */
    struct PendingDllInit {
        uint32_t entry_point;
        uint32_t base_addr;
    };
    std::vector<PendingDllInit> pending_dll_inits;

    /* Ordinal to function name mapping (coredll default + per-DLL overrides).
       Thunk() routes ordinals to the correct map based on current_dll_context. */
    static std::map<uint16_t, std::string> ordinal_map;
    static std::map<std::string, std::map<uint16_t, std::string>> dll_ordinal_map;
    std::string current_dll_context;  /* set before Register*Handlers() calls */
    std::string ResolveOrdinal(uint16_t ordinal, const std::string& dll_name = "coredll.dll");

    /* Allocate a thunk address for a function */
    uint32_t AllocThunk(const std::string& dll, const std::string& func, uint16_t ordinal, bool by_ordinal);

    /* Execute a specific thunked Win32 API call */
    bool ExecuteThunk(const ThunkEntry& entry, uint32_t* regs, EmulatedMemory& mem);

    /* Read stack arguments (beyond R0-R3) */
    uint32_t ReadStackArg(uint32_t* regs, EmulatedMemory& mem, int index);

    /* Get a native HMODULE for resource access from an emulated module handle */
    HMODULE GetNativeModuleForResources(uint32_t emu_handle);

    /* Handle mapping for 64-bit HANDLE values that can't safely round-trip
       through 32-bit ARM registers (sign-extension corrupts bit-31-set handles) */
    std::map<uint32_t, HANDLE> handle_map;   /* fake 32-bit handle -> real 64-bit HANDLE */
    uint32_t next_fake_handle = 0x00100000;

    /* File mapping tracking */
    struct FileMappingInfo {
        uint32_t emu_addr;
        uint32_t size;
    };
    std::map<uint32_t, FileMappingInfo> file_mappings; /* fake handle -> mapping info */

    /* DIB section tracking: maps emulated pvBits address -> native pvBits + size.
       Used by CreateDIBSection to let ARM code directly write bitmap pixel data. */
    uint32_t next_dib_addr = 0x04000000;  /* DIB bits allocation range */
    /* Map HBITMAP -> emulated pvBits address for GetObjectW(bmBits) */
    std::map<uint32_t, uint32_t> hbitmap_to_emu_pvbits; /* (uint32_t)HBITMAP -> emu_addr */
    uint32_t WrapHandle(HANDLE h);
    HANDLE UnwrapHandle(uint32_t fake);
    void RemoveHandle(uint32_t fake);

    /* WinCE path mapping: converts WinCE paths to host filesystem paths */
    std::wstring MapWinCEPath(const std::wstring& wce_path);
    /* Reverse mapping: converts host filesystem paths back to WinCE paths */
    std::wstring MapHostToWinCE(const std::wstring& host_path);

public:
    /* Emulated registry (file-backed, text format) */
    struct RegValue {
        uint32_t type = 0;          /* REG_DWORD, REG_SZ, REG_BINARY, etc. */
        std::vector<uint8_t> data;
    };
    struct RegKey {
        std::map<std::wstring, RegValue> values;
        std::set<std::wstring> subkeys;
    };
private:
    std::map<std::wstring, RegKey> registry;       /* full key path -> key */
    std::map<uint32_t, std::wstring> hkey_map;     /* fake HKEY -> full key path */
    uint32_t next_fake_hkey = 0xAE000000;
    bool registry_loaded = false;
    std::string registry_path;                     /* cerf_registry.txt path */
    void LoadRegistry();
    void SaveRegistry();
    void ImportRegFile(const std::string& path);
    std::wstring ResolveHKey(uint32_t hkey, const std::wstring& subkey);
    void EnsureParentKeys(const std::wstring& path);

    /* Write WIN32_FIND_DATAW to emulated memory (WinCE layout) */
    void WriteFindDataToEmu(EmulatedMemory& mem, uint32_t addr, const WIN32_FIND_DATAW& fd);

    /* Map-based thunk dispatch */
    typedef std::function<bool(uint32_t* regs, EmulatedMemory& mem)> ThunkHandler;
    std::map<std::string, ThunkHandler> thunk_handlers;

    /* Register a handler with ordinal, without ordinal, or ordinal-only (name mapping) */
    void Thunk(const std::string& name, uint16_t ordinal, ThunkHandler handler);
    void Thunk(const std::string& name, ThunkHandler handler);
    void ThunkOrdinal(const std::string& name, uint16_t ordinal);

    /* Handler registration (each in its own .cpp file) */
    void RegisterArmRuntimeHandlers();
    void RegisterMemoryHandlers();
    void RegisterCrtHandlers();
    void RegisterStringHandlers();
    void RegisterGdiDcHandlers();
    void RegisterGdiDrawHandlers();
    void RegisterGdiTextHandlers();
    void RegisterGdiRegionHandlers();
    void RegisterWindowHandlers();
    void RegisterWindowPropsHandlers();
    void RegisterDialogHandlers();
    void RegisterMessageHandlers();
    void RegisterMenuHandlers();
    void RegisterInputHandlers();
    void RegisterRegistryHandlers();
    void RegisterFileHandlers();
    void RegisterSystemHandlers();
    void RegisterResourceHandlers();
    void RegisterShellHandlers();
    void RegisterProcessHandlers();
    void RegisterMiscHandlers();
    void RegisterImageListHandlers();
    void RegisterModuleHandlers();
    void RegisterDpaHandlers();
    void RegisterDsaHandlers();
    void RegisterStdioHandlers();
    void RegisterVfsHandlers();
};
