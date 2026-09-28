#include "cerf_ndis.h"
#include "cerf_ndis_miniport.h"
#include "cerf_debug_log.h"
#include "main.h"

static const wchar_t kDriverKey[]  = L"Comm\\CERFMP";
static const wchar_t kLinkageKey[] = L"Comm\\CERFMP\\Linkage";
static const wchar_t kAdapterKey[] = L"Comm\\CERFMP1";
static const wchar_t kParmsKey[]   = L"Comm\\CERFMP1\\Parms";
static const wchar_t kTcpIpKey[]   = L"Comm\\CERFMP1\\Parms\\TcpIp";
static const wchar_t kAdapterName[] = L"CERFMP1";
static const wchar_t kGroupNdis[]  = L"NDIS";
static const wchar_t kDisplayName[] = L"CERF Guest Additions Ethernet";
static const wchar_t kCardKey[]     = L"Drivers\\CerfNdisCard";
static const wchar_t kSlotKey[]     = L"Comm\\CerfNdisSlot";
static const wchar_t kSlotKeyValue[] = L"Comm\\CerfNdisSlot";
static const wchar_t kMiniPortName[] = L"CERFMP";

static BOOL CerfNdisWriteCardKeys(void) {
    HKEY  key = 0;
    DWORD disp = 0;
    UCHAR sckt[2] = { 0, 0 };

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kSlotKey, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL,
                        &key, &disp) != ERROR_SUCCESS) return FALSE;
    RegSetValueExW(key, L"MiniPort", 0, REG_SZ, (const BYTE*)kMiniPortName,
                   sizeof(kMiniPortName));
    RegCloseKey(key);

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kCardKey, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL,
                        &key, &disp) != ERROR_SUCCESS) return FALSE;
    RegSetValueExW(key, L"Sckt", 0, REG_BINARY, sckt, sizeof(sckt));
    RegSetValueExW(key, L"Key", 0, REG_SZ, (const BYTE*)kSlotKeyValue,
                   sizeof(kSlotKeyValue));
    RegCloseKey(key);
    return TRUE;
}

static BOOL CerfNdisWriteKey(const wchar_t* path, const wchar_t* image) {
    HKEY  key = 0;
    DWORD disp = 0;
    DWORD one = 1;
    LONG  rc;

    rc = RegCreateKeyExW(HKEY_LOCAL_MACHINE, path, 0, NULL,
                         REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL,
                         &key, &disp);
    if (rc != ERROR_SUCCESS) return FALSE;

    RegSetValueExW(key, L"Group", 0, REG_SZ, (const BYTE*)kGroupNdis,
                   sizeof(kGroupNdis));
    RegSetValueExW(key, L"ImagePath", 0, REG_SZ, (const BYTE*)image,
                   (DWORD)((wcslen(image) + 1) * sizeof(wchar_t)));
    RegSetValueExW(key, L"NoDeviceCreate", 0, REG_DWORD,
                   (const BYTE*)&one, sizeof(one));
    RegSetValueExW(key, L"DisplayName", 0, REG_SZ,
                   (const BYTE*)kDisplayName, sizeof(kDisplayName));
    RegCloseKey(key);
    return TRUE;
}

BOOL CerfNdisInstall(void) {
    const CerfNdisApi* api = CerfNdisResolve();
    const wchar_t* image;
    HKEY  key = 0;
    DWORD disp = 0;
    DWORD zero = 0;
    NDIS_HANDLE out = 0;

    if (!api) return FALSE;

    if (!CerfMpNicChannelPresent()) {
        CERF_LOG("ndis: cerf_virt NIC channel absent - adapter not installed");
        return FALSE;
    }

    image = CerfInjectedModuleName();
    if (!image || !image[0]) {
        CERF_LOG("ndis: own module name unknown - cannot set ImagePath");
        return FALSE;
    }

    if (!CerfNdisWriteKey(kDriverKey, image)) return FALSE;
    if (!CerfNdisWriteKey(kAdapterKey, image)) return FALSE;

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kLinkageKey, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL,
                        &key, &disp) != ERROR_SUCCESS) return FALSE;
    {
        wchar_t route[sizeof(kAdapterName) / sizeof(wchar_t) + 1];
        memcpy(route, kAdapterName, sizeof(kAdapterName));
        route[sizeof(kAdapterName) / sizeof(wchar_t)] = 0;
        RegSetValueExW(key, L"Route", 0, REG_MULTI_SZ, (const BYTE*)route,
                       sizeof(route));
    }
    RegCloseKey(key);

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kParmsKey, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL,
                        &key, &disp) != ERROR_SUCCESS) return FALSE;
    RegSetValueExW(key, L"BusType", 0, REG_DWORD, (const BYTE*)&zero, sizeof(zero));
    RegSetValueExW(key, L"BusNumber", 0, REG_DWORD, (const BYTE*)&zero, sizeof(zero));
    RegCloseKey(key);

    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, kTcpIpKey, 0, NULL,
                        REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL,
                        &key, &disp) == ERROR_SUCCESS) {
        DWORD one = 1;
        RegSetValueExW(key, L"EnableDHCP", 0, REG_DWORD,
                       (const BYTE*)&one, sizeof(one));
        RegCloseKey(key);
    }

    if (api->RegisterAdapter) {
        NDIS_STATUS st = api->RegisterAdapter(&out, (void*)L"CERFMP",
                                              (void*)kAdapterName);
        CERF_LOG_X("ndis: NdisRegisterAdapter status", (ULONG)st);
        return st == CERF_NDIS_STATUS_SUCCESS;
    }

    if (api->NdsInit) {
        if (!CerfNdisWriteCardKeys()) return FALSE;
        api->NdsInit(kCardKey);
        if (CerfMpRegistered()) {
            CERF_LOG("ndis: miniport loaded via NDS_Init");
            return TRUE;
        }
        CERF_LOG("ndis: NDS_Init did not load the miniport");
        return FALSE;
    }

    CERF_LOG("ndis: no adapter-registration entry point on this ROM");
    return FALSE;
}
