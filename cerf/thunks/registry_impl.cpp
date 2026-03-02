#define NOMINMAX
#define _CRT_SECURE_NO_WARNINGS
#include "win32_thunks.h"
#include "../log.h"
#include <fstream>
#include <cstdio>
#include <cstring>

/* String conversion helpers (also in registry_import.cpp — static, trivial) */

static std::wstring NarrowToWide(const std::string& s) {
    std::wstring w;
    for (char c : s) w += (wchar_t)(unsigned char)c;
    return w;
}

static std::string WideToNarrow(const std::wstring& w) {
    std::string s;
    for (wchar_t c : w) s += (c < 128) ? (char)c : '?';
    return s;
}

void Win32Thunks::LoadRegistry() {
    if (registry_loaded) return;
    registry_loaded = true;

    /* Store registry in the device directory */
    registry_path = device_dir + "registry.txt";
    LOG(REG, "[REG] Loading registry from %s\n", registry_path.c_str());

    std::ifstream f(registry_path);
    if (!f.is_open()) {
        LOG(REG, "[REG] No registry file found, looking for WinCE .reg import\n");
        /* Import a WinCE registry export (.reg file) from the device directory.
           This provides default COM CLSIDs etc. */
        std::string import_path;
        {
            import_path = device_dir + "registry_to_import.reg";
            std::ifstream test(import_path);
            if (!test.is_open()) import_path = "";
        }
        if (!import_path.empty()) {
            ImportRegFile(import_path);
            SaveRegistry(); /* persist imported data */
        }
        goto post_load;
    }

    {
        std::wstring current_key;
        std::string line;
        while (std::getline(f, line)) {
            /* Trim trailing \r */
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;

            /* Key header: [HKCU\Software\...] */
            if (line[0] == '[' && line.back() == ']') {
                current_key = NarrowToWide(line.substr(1, line.size() - 2));
                registry[current_key]; /* ensure key exists */
                EnsureParentKeys(current_key);
                continue;
            }

            /* Value: "name"=type:data */
            if (current_key.empty() || line[0] != '"') continue;
            size_t eq = line.find("\"=");
            if (eq == std::string::npos || eq < 1) continue;
            std::wstring name = NarrowToWide(line.substr(1, eq - 1));
            std::string rest = line.substr(eq + 2);

            RegValue val = {};
            if (rest.substr(0, 6) == "dword:") {
                val.type = REG_DWORD;
                uint32_t dw = (uint32_t)strtoul(rest.substr(6).c_str(), nullptr, 16);
                val.data.resize(4);
                memcpy(val.data.data(), &dw, 4);
            } else if (rest.substr(0, 3) == "sz:") {
                val.type = REG_SZ;
                std::wstring ws = NarrowToWide(rest.substr(3));
                val.data.resize((ws.size() + 1) * 2);
                memcpy(val.data.data(), ws.c_str(), val.data.size());
            } else if (rest.substr(0, 4) == "hex:") {
                val.type = REG_BINARY;
                std::string hex = rest.substr(4);
                for (size_t i = 0; i < hex.size(); i += 3) {
                    val.data.push_back((uint8_t)strtoul(hex.substr(i, 2).c_str(), nullptr, 16));
                }
            }
            registry[current_key].values[name] = val;
        }
        LOG(REG, "[REG] Loaded %zu keys\n", registry.size());
    }

post_load:

    /* Pre-populate essential WinCE shell COM CLSIDs if not already present.
       The WinCE shell (ceshell.dll) uses registry lookups to find COM object
       implementations (IShellFolder, etc.). Without these entries, the shell
       namespace code fails and file dialogs call EndDialog immediately. */
    auto ensureShellClsid = [&](const wchar_t* clsid, const wchar_t* dll) {
        std::wstring key = std::wstring(L"HKCR\\CLSID\\") + clsid;
        std::wstring ips32 = key + L"\\InProcServer32";
        if (registry.find(key) == registry.end()) {
            registry[key];
            EnsureParentKeys(key);
            registry[ips32];
            EnsureParentKeys(ips32);
            /* Default value = DLL name */
            RegValue val;
            val.type = REG_SZ;
            std::wstring ws(dll);
            val.data.resize((ws.size() + 1) * 2);
            memcpy(val.data.data(), ws.c_str(), val.data.size());
            registry[ips32].values[L""] = val;
            LOG(REG, "[REG] Pre-populated CLSID %ls -> %ls\n", clsid, dll);
        }
    };
    /* IShellFolder — shell desktop/folder namespace */
    ensureShellClsid(L"{000214A0-0000-0000-C000-000000000046}", L"ceshell.dll");
    /* ShellDesktop — CLSID_ShellDesktop */
    ensureShellClsid(L"{00021400-0000-0000-C000-000000000046}", L"ceshell.dll");
}

void Win32Thunks::SaveRegistry() {
    if (registry_path.empty()) return;

    std::ofstream f(registry_path);
    if (!f.is_open()) {
        LOG(REG, "[REG] Failed to save registry to %s\n", registry_path.c_str());
        return;
    }

    for (auto& [path, key] : registry) {
        if (key.values.empty()) continue;
        f << "[" << WideToNarrow(path) << "]\n";
        for (auto& [name, val] : key.values) {
            f << "\"" << WideToNarrow(name) << "\"=";
            if (val.type == REG_DWORD && val.data.size() >= 4) {
                uint32_t dw;
                memcpy(&dw, val.data.data(), 4);
                char buf[16];
                sprintf(buf, "dword:%08X", dw);
                f << buf << "\n";
            } else if (val.type == REG_SZ || val.type == REG_EXPAND_SZ) {
                std::wstring ws((const wchar_t*)val.data.data(), val.data.size() / 2);
                if (!ws.empty() && ws.back() == L'\0') ws.pop_back();
                f << "sz:" << WideToNarrow(ws) << "\n";
            } else {
                f << "hex:";
                for (size_t i = 0; i < val.data.size(); i++) {
                    char buf[4];
                    sprintf(buf, "%s%02X", i > 0 ? "," : "", val.data[i]);
                    f << buf;
                }
                f << "\n";
            }
        }
        f << "\n";
    }
    LOG(REG, "[REG] Saved %zu keys to %s\n", registry.size(), registry_path.c_str());
}

std::wstring Win32Thunks::ResolveHKey(uint32_t hkey, const std::wstring& subkey) {
    std::wstring root;

    /* Predefined HKEY constants (WinCE uses the same values) */
    if (hkey == 0x80000000) root = L"HKCR";
    else if (hkey == 0x80000001) root = L"HKCU";
    else if (hkey == 0x80000002) root = L"HKLM";
    else if (hkey == 0x80000003) root = L"HKU";
    else {
        /* Look up fake HKEY */
        auto it = hkey_map.find(hkey);
        if (it != hkey_map.end()) root = it->second;
        else root = L"HKCU"; /* fallback */
    }

    if (subkey.empty()) return root;

    /* Strip leading backslash from subkey */
    std::wstring sk = subkey;
    while (!sk.empty() && (sk[0] == L'\\' || sk[0] == L'/')) sk.erase(sk.begin());
    if (sk.empty()) return root;

    /* Normalize separators */
    std::wstring full = root + L"\\" + sk;
    /* Remove trailing backslash */
    while (!full.empty() && full.back() == L'\\') full.pop_back();
    return full;
}

void Win32Thunks::EnsureParentKeys(const std::wstring& path) {
    /* Make sure all parent keys exist and have subkey references */
    size_t pos = 0;
    while ((pos = path.find(L'\\', pos + 1)) != std::wstring::npos) {
        std::wstring parent = path.substr(0, pos);
        std::wstring child_name = path.substr(pos + 1);
        size_t next = child_name.find(L'\\');
        if (next != std::wstring::npos) child_name = child_name.substr(0, next);
        registry[parent].subkeys.insert(child_name);
    }
}
