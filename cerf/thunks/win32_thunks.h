#pragma once
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <functional>
#include <atomic>
#include "../cpu/mem.h"
#include "../loader/pe_loader.h"
#include "thread_context.h"

/* Thunked DLL registry — add one entry here, then create Register*Handlers(). */
struct ThunkedDllInfo {
    const char* name;          /* lowercase key (e.g. "coredll") */
    uint32_t    fake_handle;   /* returned by GetModuleHandle/LoadLibrary */
};
extern const ThunkedDllInfo thunked_dlls[];
extern const size_t thunked_dlls_count;
const ThunkedDllInfo* FindThunkedDll(const std::string& dll_name);   /* case-insensitive substring */
const ThunkedDllInfo* FindThunkedDllW(const std::wstring& dll_name); /* wide version */

/* Thunk address range (0xF000xxxx reserved for WinCE kernel trap API calls) */
#define THUNK_BASE   0xFE000000
#define THUNK_STRIDE 4
#define WINCE_SCREEN_WIDTH_DEFAULT   800
#define WINCE_SCREEN_HEIGHT_DEFAULT  480
/* WinCE trap-based API range: index = (0xF0010000 - addr) / 4 */
#define WINCE_TRAP_BASE  0xF0000000
#define WINCE_TRAP_TOP   0xF0010000

struct ThunkEntry {
    std::string dll_name;
    std::string func_name;
    uint16_t    ordinal;
    bool        by_ordinal;
    uint32_t    thunk_addr;
};

std::wstring ReadWStringFromEmu(EmulatedMemory& mem, uint32_t addr);
std::string ReadStringFromEmu(EmulatedMemory& mem, uint32_t addr);
bool IsArmPE(const std::wstring& host_path); /* Check if file is ARM PE (WinCE) */

class Win32Thunks {
public:
    Win32Thunks(EmulatedMemory& mem);
    void InstallThunks(PEInfo& info);      /* Replace IAT entries with thunk addresses */
    void CallDllEntryPoints();             /* Call DllMain for loaded ARM DLLs */
    bool HandleThunk(uint32_t addr, uint32_t* regs, EmulatedMemory& mem);

    void SetHInstance(uint32_t hinst) { emu_hinstance = hinst; }
    void SetExePath(const std::wstring& path) { exe_path = path; }
    void SetExeDir(const std::string& dir) { exe_dir = dir; }

    void InitVFS(const std::string& device_override = "");

    /* Callback executor: trampoline to t_ctx->callback_executor (per-thread) */
    typedef std::function<uint32_t(uint32_t addr, uint32_t* args, int nargs)> CallbackExecutor;
    CallbackExecutor callback_executor;

    std::atomic<uint32_t> next_tls_slot{4};  /* TLS slot allocator (0-3 reserved) */
    std::map<uint32_t, CRITICAL_SECTION*> cs_map; /* ARM CS addr -> native CS* */
    std::mutex cs_map_mutex;

    std::map<std::wstring, uint32_t> arm_wndprocs;             /* class name -> ARM WndProc */
    static std::map<HWND, uint32_t> hwnd_wndproc_map;          /* HWND -> ARM WndProc */
    static std::map<HWND, WNDPROC> hwnd_native_wndproc_map;   /* HWND -> saved native WndProc before EmuWndProc subclass */
    static std::map<UINT_PTR, uint32_t> arm_timer_callbacks;   /* timer ID -> ARM TIMERPROC */
    static std::map<HWND, uint32_t> hwnd_dlgproc_map;          /* HWND -> ARM DlgProc */
    static uint32_t pending_arm_dlgproc;   /* stashed for CreateDialogIndirectParamW */
    /* Original WinCE window styles — stored per-HWND because we convert top-level
       windows to WS_POPUP on desktop, but ARM code needs to see original styles. */
    static std::map<HWND, uint32_t> hwnd_wce_style_map;
    static std::map<HWND, uint32_t> hwnd_wce_exstyle_map;
    /* Thread-local pending WinCE styles for CreateWindowExW → EmuWndProc handoff.
       Set before ::CreateWindowExW, consumed during WM_NCCREATE in EmuWndProc. */
    static thread_local uint32_t tls_pending_wce_style;
    static thread_local uint32_t tls_pending_wce_exstyle;
    static std::set<HWND> captionok_hwnds; /* WS_EX_CAPTIONOKBTN tracking */
    static INT_PTR modal_dlg_result;
    static bool modal_dlg_ended;
    static Win32Thunks* s_instance;
    static thread_local HWND tls_paint_hwnd; /* last WM_PAINT target per thread */
    std::vector<uint32_t> setjmp_stack;    /* RaiseException recovery */

    static LRESULT CALLBACK EmuWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static INT_PTR CALLBACK EmuDlgProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static LRESULT CALLBACK MenuBarWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    static void InstallCaptionOk(HWND hwnd);
    static void RemoveCaptionOk(HWND hwnd);
private:
    static LRESULT CALLBACK CaptionOkSubclassProc(HWND, UINT, WPARAM, LPARAM, UINT_PTR, DWORD_PTR);

    EmulatedMemory& mem;
    std::map<uint32_t, ThunkEntry> thunks;   /* thunk_addr -> entry */
    uint32_t next_thunk_addr;
    uint32_t emu_hinstance;
    std::wstring exe_path;
    std::string exe_dir;
    std::string wince_sys_dir;

    /* WinCE system font (from HKLM\System\GDI\SYSFNT) */
    std::wstring wce_sysfont_name = L"Tahoma";
    LONG wce_sysfont_height = -12;
    LONG wce_sysfont_weight = FW_NORMAL;
    void InitWceSysFont();

public:
    /* Emulated screen resolution (from cerf.ini) */
    bool fake_screen_resolution = true;
    uint32_t screen_width  = WINCE_SCREEN_WIDTH_DEFAULT;
    uint32_t screen_height = WINCE_SCREEN_HEIGHT_DEFAULT;
    /* Emulated work area — initially full screen, reduced by SPI_SETWORKAREA
       when the shell (taskbar) reserves space.  {0,0,0,0} = use full screen. */
    RECT work_area = {};
    RECT GetWorkArea() const {
        if (work_area.right > 0 || work_area.bottom > 0) return work_area;
        return {0, 0, (LONG)screen_width, (LONG)screen_height};
    }
    /* Emulated WinCE OS version */
    uint32_t os_major = 5;
    uint32_t os_minor = 0;
    uint32_t os_build = 1;
    std::string os_build_date = "Jan  1 2008";
    uint32_t fake_total_phys = 0;  /* fake memory; 0 = use real host memory */
    /* WinCE theming */
    bool enable_theming = false;
    bool disable_uxtheme = false;
    void InitWceTheme();
    void ApplyWindowTheme(HWND hwnd, bool is_toplevel);
    void UpdateWceThemeColor(int index, COLORREF color);
    COLORREF GetWceThemeColor(int index);
    HBRUSH GetWceThemeBrush(int index);

private:
    /* Virtual filesystem device paths */
    std::string cerf_dir;
    std::string device_name;
    std::string device_fs_root;
    std::string device_dir;

    struct LoadedDll {
        std::string path;
        uint32_t base_addr;
        PEInfo pe_info;
        HMODULE native_rsrc_handle;
    };
    std::map<std::wstring, LoadedDll> loaded_dlls;
    LoadedDll* LoadArmDll(const std::string& dll_name);

    struct EmuRsrc { uint32_t data_rva; uint32_t data_size; uint32_t module_base; };
    std::map<uint32_t, EmuRsrc> rsrc_map;
    uint32_t next_rsrc_handle = 0xE0000000;
    uint32_t FindResourceInPE(uint32_t module_base, uint32_t rsrc_rva, uint32_t rsrc_size,
                              uint32_t type_id, uint32_t name_id,
                              uint32_t& out_data_rva, uint32_t& out_data_size);

    struct PendingDllInit { uint32_t entry_point; uint32_t base_addr; };
    std::vector<PendingDllInit> pending_dll_inits;

    /* Ordinal to function name mapping */
    static std::map<uint16_t, std::string> ordinal_map;
    std::string ResolveOrdinal(uint16_t ordinal);

    uint32_t AllocThunk(const std::string& dll, const std::string& func, uint16_t ordinal, bool by_ordinal);
    bool ExecuteThunk(ThunkEntry& entry, uint32_t* regs, EmulatedMemory& mem);
    uint32_t ReadStackArg(uint32_t* regs, EmulatedMemory& mem, int index);
    HMODULE GetNativeModuleForResources(uint32_t emu_handle);

    /* Handle mapping (64-bit HANDLE <-> 32-bit fake handle for ARM round-trip) */
    std::map<uint32_t, HANDLE> handle_map;
    uint32_t next_fake_handle = 0x00100000;
    struct FileMappingInfo { uint32_t emu_addr; uint32_t size; };
    std::map<uint32_t, FileMappingInfo> file_mappings;

    /* DIB section tracking */
    uint32_t next_dib_addr = 0x04000000;
    std::map<uint32_t, uint32_t> hbitmap_to_emu_pvbits; /* HBITMAP -> emu pvBits addr */
    uint32_t WrapHandle(HANDLE h);
    HANDLE UnwrapHandle(uint32_t fake);
    void RemoveHandle(uint32_t fake);

    std::wstring MapWinCEPath(const std::wstring& wce_path);
    std::wstring MapHostToWinCE(const std::wstring& host_path);

public:
    /* Emulated registry (file-backed, text format) */
    struct RegValue { uint32_t type = 0; std::vector<uint8_t> data; };
    /* Case-insensitive comparator for registry value names (Windows registry is case-insensitive) */
    struct WstrCILess {
        bool operator()(const std::wstring& a, const std::wstring& b) const {
            return _wcsicmp(a.c_str(), b.c_str()) < 0;
        }
    };
    struct RegKey { std::map<std::wstring, RegValue, WstrCILess> values; std::set<std::wstring, WstrCILess> subkeys; };
private:
    std::map<std::wstring, RegKey, WstrCILess> registry;
    std::map<uint32_t, std::wstring> hkey_map;
    uint32_t next_fake_hkey = 0xAE000000;
    bool registry_loaded = false;
    std::string registry_path;
    std::recursive_mutex registry_mutex; /* Protects registry, hkey_map, next_fake_hkey */
    void LoadRegistry();
    void SaveRegistry();
    void ImportRegFile(const std::string& path);
    std::wstring ResolveHKey(uint32_t hkey, const std::wstring& subkey);
    void EnsureParentKeys(const std::wstring& path);
    /* Internal registry helpers — handle locking + LoadRegistry internally */
    bool RegGetValue(const std::wstring& key, const std::wstring& name, RegValue& out);
    void RegSetValue(const std::wstring& key, const std::wstring& name, const RegValue& val);
    bool ResolveMuiString(const std::wstring& mui_ref, std::wstring& resolved);
    void WriteFindDataToEmu(EmulatedMemory& mem, uint32_t addr, const WIN32_FIND_DATAW& fd);

    /* Map-based thunk dispatch */
    typedef std::function<bool(uint32_t* regs, EmulatedMemory& mem)> ThunkHandler;
    std::map<std::string, ThunkHandler> thunk_handlers;
    void Thunk(const std::string& name, uint16_t ordinal, ThunkHandler handler);
    void Thunk(const std::string& name, ThunkHandler handler);
    void ThunkOrdinal(const std::string& name, uint16_t ordinal);

    /* Handler registration (each in its own .cpp file) */
    void RegisterArmRuntimeHandlers();
    void RegisterMemoryHandlers();
    void RegisterCrtHandlers();
    void RegisterStringHandlers();
    void RegisterStringFormatHandlers();
    void RegisterStringSafeHandlers();
    std::wstring WprintfFormat(EmulatedMemory& mem, const std::wstring& fmt, uint32_t* args, int nargs);
    void RegisterGdiDcHandlers();
    void RegisterGdiDrawHandlers();
    void RegisterGdiTextHandlers();
    void RegisterGdiRegionHandlers();
    void RegisterWindowHandlers();
    void RegisterWindowLayoutHandlers();
    void RegisterWindowPropsHandlers();
    void RegisterDialogHandlers();
    void RegisterMessageHandlers();
    void RegisterMenuHandlers();
    void RegisterInputHandlers();
    void RegisterRegistryHandlers();
    void RegisterFileHandlers();
    void RegisterFileNotifyHandlers();
    void RegisterSystemHandlers();
    void RegisterSysInfoHandlers();
    void RegisterLocaleHandlers();
    void RegisterSyncHandlers();
    void RegisterResourceHandlers();
    void RegisterShellHandlers();
    void RegisterProcessHandlers();
    void RegisterChildProcessHandler();
    void RegisterFileMappingHandlers();
    void RegisterMiscHandlers();
    void RegisterComHandlers();
    void RegisterImageListHandlers();
    void RegisterModuleHandlers();
    void RegisterDpaHandlers();
    void RegisterDsaHandlers();
    void RegisterStdioHandlers();
    void RegisterVfsHandlers();
    void RegisterShellExecHandler();
    void RegisterWinsockHandlers();
    void RegisterWinsockDnsHandlers();
    void RegisterWininetDepsHandlers();
    bool LaunchArmChildProcess(const std::wstring& mapped_file, const std::wstring& params,
                               uint32_t sei_addr, uint32_t* regs, EmulatedMemory& mem);
};
