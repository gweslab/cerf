#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../log.h"
#include <cstdio>
#include <algorithm>
#include <set>

/* Check if a DLL name refers to a system DLL that we thunk (not an ARM DLL) */
static bool IsThunkedDll(const std::string& dll_name) {
    return FindThunkedDll(dll_name) != nullptr;
}

/* Try to find and load an ARM DLL by name.
   Returns pointer to LoadedDll if found, or nullptr.
   Searches: loaded_dlls cache, exe_dir, wince_sys_dir. */
Win32Thunks::LoadedDll* Win32Thunks::LoadArmDll(const std::string& dll_name) {
    std::string lower = dll_name;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    std::wstring wlower(lower.begin(), lower.end());

    /* Already loaded? */
    auto it = loaded_dlls.find(wlower);
    if (it != loaded_dlls.end()) return &it->second;

    /* Try to find the ARM DLL file */
    std::string dll_path = exe_dir + dll_name;
    FILE* f = fopen(dll_path.c_str(), "rb");
    if (!f && !wince_sys_dir.empty()) {
        dll_path = wince_sys_dir + dll_name;
        f = fopen(dll_path.c_str(), "rb");
    }
    if (!f) {
        dll_path = dll_name;
        f = fopen(dll_path.c_str(), "rb");
    }
    if (!f) return nullptr;
    fclose(f);

    PEInfo dll_info = {};
    uint32_t entry = PELoader::LoadDll(dll_path.c_str(), mem, dll_info);
    if (entry == 0 && dll_info.image_base == 0) {
        LOG(THUNK, "[THUNK] Failed to load ARM DLL: %s\n", dll_path.c_str());
        return nullptr;
    }

    LOG(THUNK, "[THUNK] Loaded ARM DLL '%s' at 0x%08X (exports: RVA=0x%X size=0x%X)\n",
           dll_name.c_str(), dll_info.image_base, dll_info.export_rva, dll_info.export_size);

    LoadedDll loaded;
    loaded.path = dll_path;
    loaded.base_addr = dll_info.image_base;
    loaded.pe_info = dll_info;
    loaded.native_rsrc_handle = NULL;
    loaded_dlls[wlower] = loaded;

    /* Recursively install thunks for this DLL's own imports */
    InstallThunks(loaded_dlls[wlower].pe_info);

    /* Queue DLL entry point (DllMain) for deferred call after CPU init */
    if (entry != 0 && dll_info.entry_point_rva != 0) {
        LOG(THUNK, "[THUNK]  DLL has entry point at 0x%08X - queued for init\n", entry);
        pending_dll_inits.push_back({entry, dll_info.image_base});
    }

    return &loaded_dlls[wlower];
}

void Win32Thunks::InstallThunks(PEInfo& info) {
    /* For each import, try to resolve from a loaded ARM DLL first,
       then fall back to creating a thunk stub. ARM DLLs are loaded
       on demand (cascading: their imports are resolved recursively). */
    std::set<std::string> warned_dlls;
    for (auto& imp : info.imports) {
        /* Thunked system DLL (coredll) — always create a thunk */
        if (IsThunkedDll(imp.dll_name)) {
            uint32_t thunk_addr = AllocThunk(imp.dll_name, imp.func_name, imp.ordinal, imp.by_ordinal);
            mem.Write32(imp.iat_addr, thunk_addr);
            if (imp.by_ordinal) {
                LOG(THUNK, "[THUNK] Installed thunk for %s!@%d at 0x%08X -> IAT 0x%08X\n",
                       imp.dll_name.c_str(), imp.ordinal, thunk_addr, imp.iat_addr);
            } else {
                LOG(THUNK, "[THUNK] Installed thunk for %s!%s at 0x%08X -> IAT 0x%08X\n",
                       imp.dll_name.c_str(), imp.func_name.c_str(), thunk_addr, imp.iat_addr);
            }
            continue;
        }

        /* Try to load/find the ARM DLL */
        LoadedDll* arm_dll = LoadArmDll(imp.dll_name);
        if (arm_dll) {
            /* Resolve the export from the ARM DLL */
            uint32_t arm_addr = 0;
            if (imp.by_ordinal) {
                arm_addr = PELoader::ResolveExportOrdinal(mem, arm_dll->pe_info, imp.ordinal);
            } else {
                arm_addr = PELoader::ResolveExportName(mem, arm_dll->pe_info, imp.func_name);
            }

            if (arm_addr != 0) {
                mem.Write32(imp.iat_addr, arm_addr);
                if (imp.by_ordinal) {
                    LOG(THUNK, "[THUNK] Resolved %s!@%d -> ARM 0x%08X (IAT 0x%08X)\n",
                           imp.dll_name.c_str(), imp.ordinal, arm_addr, imp.iat_addr);
                } else {
                    LOG(THUNK, "[THUNK] Resolved %s!%s -> ARM 0x%08X (IAT 0x%08X)\n",
                           imp.dll_name.c_str(), imp.func_name.c_str(), arm_addr, imp.iat_addr);
                }
                continue;
            }
            LOG(THUNK, "[THUNK] WARNING: Export not found in %s for %s@%d, using thunk stub\n",
                   imp.dll_name.c_str(), imp.func_name.c_str(), imp.ordinal);
        } else {
            if (warned_dlls.insert(imp.dll_name).second) {
                LOG_ERR("[THUNK] ERROR: DLL not found: %s — imports will fail at runtime!\n", imp.dll_name.c_str());
            }
        }

        /* Unresolved — create a thunk stub that will log loudly if called */
        uint32_t thunk_addr = AllocThunk(imp.dll_name, imp.func_name, imp.ordinal, imp.by_ordinal);
        mem.Write32(imp.iat_addr, thunk_addr);
        if (imp.by_ordinal) {
            LOG(THUNK, "[THUNK] Installed thunk for %s!@%d at 0x%08X -> IAT 0x%08X\n",
                   imp.dll_name.c_str(), imp.ordinal, thunk_addr, imp.iat_addr);
        } else {
            LOG(THUNK, "[THUNK] Installed thunk for %s!%s at 0x%08X -> IAT 0x%08X\n",
                   imp.dll_name.c_str(), imp.func_name.c_str(), thunk_addr, imp.iat_addr);
        }
    }
}

void Win32Thunks::CallDllEntryPoints() {
    if (!callback_executor || pending_dll_inits.empty()) return;

    for (auto& init : pending_dll_inits) {
        LOG(THUNK, "[THUNK] Calling DllMain at 0x%08X (base=0x%08X, DLL_PROCESS_ATTACH)\n",
               init.entry_point, init.base_addr);
        /* DllMain(hinstDLL, DLL_PROCESS_ATTACH, lpvReserved)
           R0 = hinstDLL (DLL base address)
           R1 = fdwReason = 1 (DLL_PROCESS_ATTACH)
           R2 = lpvReserved = 0 */
        uint32_t args[3] = { init.base_addr, 1, 0 };
        uint32_t result = callback_executor(init.entry_point, args, 3);
        LOG(THUNK, "[THUNK] DllMain returned %d\n", result);
    }
    pending_dll_inits.clear();
}
