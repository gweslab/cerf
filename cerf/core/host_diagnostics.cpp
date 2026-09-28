#define NOMINMAX
#include "host_diagnostics.h"

#include "cerf_paths.h"
#include "log.h"
#include "string_utils.h"

#include <windows.h>

#include <cstdio>
#include <string>

namespace {

constexpr wchar_t kNtCurrentVersion[] =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion";
constexpr wchar_t kCompatLayers[] =
    L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers";
constexpr wchar_t kCpu0[] =
    L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0";

bool RegRead(HKEY root, const wchar_t* path, const wchar_t* name,
             DWORD want_type, void* data, DWORD size) {
    HKEY key = nullptr;
    if (RegOpenKeyExW(root, path, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY,
                      &key) != ERROR_SUCCESS)
        return false;
    DWORD type = 0;
    const LONG rc = RegQueryValueExW(key, name, nullptr, &type,
                                     static_cast<BYTE*>(data), &size);
    RegCloseKey(key);
    return rc == ERROR_SUCCESS && type == want_type;
}

std::string Trimmed(const std::string& s) {
    const size_t first = s.find_first_not_of(' ');
    if (first == std::string::npos) return {};
    return s.substr(first, s.find_last_not_of(' ') - first + 1);
}

std::string RegString(HKEY root, const wchar_t* path, const wchar_t* name) {
    wchar_t buf[512] = {};
    if (!RegRead(root, path, name, REG_SZ, buf, sizeof(buf) - sizeof(wchar_t)))
        return {};
    return Trimmed(WideToUtf8(buf));
}

bool RegDword(HKEY root, const wchar_t* path, const wchar_t* name,
              DWORD& out) {
    return RegRead(root, path, name, REG_DWORD, &out, sizeof(out));
}

std::string EnvString(const wchar_t* name) {
    const DWORD need = GetEnvironmentVariableW(name, nullptr, 0);
    if (need == 0) return {};
    std::wstring buf(need, L'\0');
    const DWORD n = GetEnvironmentVariableW(name, &buf[0], need);
    if (n == 0 || n >= need) return {};
    buf.resize(n);
    return WideToUtf8(buf);
}

std::wstring CurrentDirectory() {
    const DWORD need = GetCurrentDirectoryW(0, nullptr);
    if (need == 0) return {};
    std::wstring buf(need, L'\0');
    const DWORD n = GetCurrentDirectoryW(need, &buf[0]);
    if (n == 0 || n >= need) return {};
    buf.resize(n);
    return buf;
}

void Join(std::string& out, const std::string& part) {
    if (part.empty()) return;
    if (!out.empty()) out += ", ";
    out += part;
}

const char* OrNone(const std::string& s) {
    return s.empty() ? "(none)" : s.c_str();
}

USHORT MachineFromArchitecture(WORD arch) {
    switch (arch) {
        case PROCESSOR_ARCHITECTURE_INTEL: return IMAGE_FILE_MACHINE_I386;
        case PROCESSOR_ARCHITECTURE_AMD64: return IMAGE_FILE_MACHINE_AMD64;
        case PROCESSOR_ARCHITECTURE_IA64:  return IMAGE_FILE_MACHINE_IA64;
        case PROCESSOR_ARCHITECTURE_ARM:   return IMAGE_FILE_MACHINE_ARMNT;
        case PROCESSOR_ARCHITECTURE_ARM64: return IMAGE_FILE_MACHINE_ARM64;
        default:                           return IMAGE_FILE_MACHINE_UNKNOWN;
    }
}

std::string MachineName(USHORT machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_I386:  return "x86";
        case IMAGE_FILE_MACHINE_AMD64: return "x64";
        case IMAGE_FILE_MACHINE_IA64:  return "IA64";
        case IMAGE_FILE_MACHINE_ARMNT: return "ARM";
        case IMAGE_FILE_MACHINE_ARM64: return "ARM64";
        default: {
            char buf[16];
            snprintf(buf, sizeof(buf), "0x%04X", (unsigned)machine);
            return buf;
        }
    }
}

void LogOs() {
    using RtlGetVersionFn = LONG(WINAPI*)(OSVERSIONINFOEXW*);
    const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    const auto rtl_get_version = reinterpret_cast<RtlGetVersionFn>(
        GetProcAddress(ntdll, "RtlGetVersion"));
    std::string kernel = "unknown";
    OSVERSIONINFOEXW v = {};
    v.dwOSVersionInfoSize = sizeof(v);
    if (rtl_get_version && rtl_get_version(&v) == 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "%lu.%lu.%lu", v.dwMajorVersion,
                 v.dwMinorVersion, v.dwBuildNumber);
        kernel = buf;
    }

    std::string reg;
    Join(reg, RegString(HKEY_LOCAL_MACHINE, kNtCurrentVersion, L"ProductName"));
    Join(reg, RegString(HKEY_LOCAL_MACHINE, kNtCurrentVersion, L"EditionID"));
    std::string release =
        RegString(HKEY_LOCAL_MACHINE, kNtCurrentVersion, L"DisplayVersion");
    if (release.empty())
        release = RegString(HKEY_LOCAL_MACHINE, kNtCurrentVersion, L"ReleaseId");
    Join(reg, release);
    Join(reg, RegString(HKEY_LOCAL_MACHINE, kNtCurrentVersion, L"CSDVersion"));
    std::string build =
        RegString(HKEY_LOCAL_MACHINE, kNtCurrentVersion, L"CurrentBuildNumber");
    DWORD ubr = 0;
    if (!build.empty() &&
        RegDword(HKEY_LOCAL_MACHINE, kNtCurrentVersion, L"UBR", ubr))
        build += "." + std::to_string(ubr);
    if (!build.empty()) Join(reg, "build " + build);
    LOG(Cerf, "Host OS: Windows NT %s; registry: %s\n", kernel.c_str(),
        OrNone(reg));

    using WineGetVersionFn     = const char*(__cdecl*)();
    using WineGetHostVersionFn = void(__cdecl*)(const char**, const char**);
    const auto wine_get_version = reinterpret_cast<WineGetVersionFn>(
        GetProcAddress(ntdll, "wine_get_version"));
    if (!wine_get_version) return;
    const auto wine_get_host_version = reinterpret_cast<WineGetHostVersionFn>(
        GetProcAddress(ntdll, "wine_get_host_version"));
    const char* sysname = nullptr;
    const char* release_name = nullptr;
    if (wine_get_host_version) wine_get_host_version(&sysname, &release_name);
    LOG(Cerf, "Host OS: Wine %s on %s %s\n", wine_get_version(),
        sysname ? sysname : "unknown", release_name ? release_name : "");
}

void LogCpu() {
    SYSTEM_INFO si = {};
    GetNativeSystemInfo(&si);

    using IsWow64Process2Fn = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);
    using IsWow64ProcessFn  = BOOL(WINAPI*)(HANDLE, PBOOL);
    const HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    const auto is_wow64_process2 = reinterpret_cast<IsWow64Process2Fn>(
        GetProcAddress(kernel32, "IsWow64Process2"));
    USHORT process_machine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT native_machine  = IMAGE_FILE_MACHINE_UNKNOWN;
    bool wow64 = false;
    if (is_wow64_process2 &&
        is_wow64_process2(GetCurrentProcess(), &process_machine,
                          &native_machine)) {
        wow64 = process_machine != IMAGE_FILE_MACHINE_UNKNOWN;
    } else {
        native_machine = MachineFromArchitecture(si.wProcessorArchitecture);
        const auto is_wow64_process = reinterpret_cast<IsWow64ProcessFn>(
            GetProcAddress(kernel32, "IsWow64Process"));
        BOOL flag = FALSE;
        wow64 = is_wow64_process &&
                is_wow64_process(GetCurrentProcess(), &flag) && flag;
    }

    const std::string name =
        RegString(HKEY_LOCAL_MACHINE, kCpu0, L"ProcessorNameString");
    LOG(Cerf, "Host CPU: %s; %lu logical processors; native %s; cerf.exe %s\n",
        name.empty() ? "unknown" : name.c_str(), si.dwNumberOfProcessors,
        MachineName(native_machine).c_str(),
        wow64 ? "runs under WOW64" : "runs natively");
}

void LogMemory() {
    MEMORYSTATUSEX m = {};
    m.dwLength = sizeof(m);
    if (!GlobalMemoryStatusEx(&m)) {
        LOG(Cerf, "Host memory: GlobalMemoryStatusEx failed (gle=%lu)\n",
            GetLastError());
        return;
    }
    LOG(Cerf, "Host memory: %llu MB physical, %llu MB available; cerf.exe "
        "address space %llu MB\n",
        m.ullTotalPhys >> 20, m.ullAvailPhys >> 20, m.ullTotalVirtual >> 20);
}

void LogLocale() {
    wchar_t lang[16] = {};
    wchar_t country[16] = {};
    GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SISO639LANGNAME, lang, 16);
    GetLocaleInfoW(LOCALE_USER_DEFAULT, LOCALE_SISO3166CTRYNAME, country, 16);
    LOG(Cerf, "Host locale: %s-%s; ANSI code page %u; OEM code page %u\n",
        WideToUtf8(lang).c_str(), WideToUtf8(country).c_str(), GetACP(),
        GetOEMCP());
}

void LogProcess() {
    const char* elevated = "unknown";
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elevation = {};
        DWORD got = 0;
        if (GetTokenInformation(token, TokenElevation, &elevation,
                                sizeof(elevation), &got))
            elevated = elevation.TokenIsElevated ? "yes" : "no";
        CloseHandle(token);
    }

    const std::wstring exe = GetCerfExePath();
    std::string layers;
    const std::string user_layer =
        exe.empty() ? std::string()
                    : RegString(HKEY_CURRENT_USER, kCompatLayers, exe.c_str());
    const std::string machine_layer =
        exe.empty() ? std::string()
                    : RegString(HKEY_LOCAL_MACHINE, kCompatLayers, exe.c_str());
    const std::string env_layer = EnvString(L"__COMPAT_LAYER");
    if (!user_layer.empty()) Join(layers, "user '" + user_layer + "'");
    if (!machine_layer.empty()) Join(layers, "machine '" + machine_layer + "'");
    if (!env_layer.empty()) Join(layers, "__COMPAT_LAYER '" + env_layer + "'");

    LOG(Cerf, "Process: elevated %s; compatibility layers %s\n", elevated,
        OrNone(layers));
    LOG(Cerf, "Process executable: %s\n", OrNone(WideToUtf8(exe)));
    LOG(Cerf, "Process working directory: %s\n",
        OrNone(WideToUtf8(CurrentDirectory())));
    LOG(Cerf, "Process command line: %s\n", WideToUtf8(GetCommandLineW()).c_str());
}

}  // namespace

void HostDiagnostics::LogReport() {
    LogOs();
    LogCpu();
    LogMemory();
    LogLocale();
    LogProcess();
}
