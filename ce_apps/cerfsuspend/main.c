#include <windows.h>

typedef void (WINAPI *PFN_OutputDebugStringW)(LPCWSTR);
typedef void (WINAPI *PFN_PowerOffSystem)(void);
typedef LPVOID (WINAPI *PFN_VirtualAlloc)(LPVOID, DWORD, DWORD, DWORD);
typedef BOOL (WINAPI *PFN_VirtualCopy)(LPVOID, LPVOID, DWORD, DWORD);

#define CERF_PAGE_PHYSICAL 0x400u

static PFN_OutputDebugStringW s_ods = NULL;

static void Say(const WCHAR* tag, DWORD a)
{
    WCHAR        buf[96];
    int          n = 0;
    int          i;
    const WCHAR* p;
    if (s_ods == NULL) return;
    for (p = L"cerfsuspend: "; *p && n < 80; ++p) buf[n++] = *p;
    for (p = tag; *p && n < 80; ++p) buf[n++] = *p;
    buf[n++] = L' ';
    for (i = 28; i >= 0; i -= 4) buf[n++] = L"0123456789ABCDEF"[(a >> i) & 0xFu];
    buf[n++] = L'\r';
    buf[n++] = L'\n';
    buf[n]   = 0;
    s_ods(buf);
}

static volatile DWORD* MapPage(HMODULE core, DWORD pa)
{
    PFN_VirtualAlloc valloc = (PFN_VirtualAlloc)GetProcAddressW(core, L"VirtualAlloc");
    PFN_VirtualCopy  vcopy  = (PFN_VirtualCopy)GetProcAddressW(core, L"VirtualCopy");
    LPVOID           va;
    if (valloc == NULL || vcopy == NULL) {
        Say(L"no VirtualCopy", 0);
        return NULL;
    }
    va = valloc(NULL, 0x1000, MEM_RESERVE, PAGE_NOACCESS);
    if (va == NULL) {
        Say(L"VirtualAlloc failed", GetLastError());
        return NULL;
    }
    if (!vcopy(va, (LPVOID)(pa >> 8), 0x1000,
               PAGE_READWRITE | PAGE_NOCACHE | CERF_PAGE_PHYSICAL)) {
        Say(L"VirtualCopy failed", GetLastError());
        return NULL;
    }
    return (volatile DWORD*)va;
}

static DWORD ToBcd(DWORD v) { return ((v / 10u) << 4) | (v % 10u); }
static DWORD FromBcd(DWORD v) { return ((v >> 4) & 0xFu) * 10u + (v & 0xFu); }

static void ArmSa11xxAlarm(HMODULE core, DWORD secs)
{
    volatile DWORD* rtc = MapPage(core, 0x90010000u);
    DWORD           rcnr;
    if (rtc == NULL) return;
    rcnr    = rtc[1];
    rtc[0]  = rcnr + secs;
    rtc[4]  = (rtc[4] & 0x8u) | 0x4u;
    Say(L"sa11xx alarm rcnr", rcnr);
    Say(L"sa11xx alarm rtar", rtc[0]);
    Say(L"sa11xx alarm rtsr", rtc[4]);
}

static void ArmS3c2410Alarm(HMODULE core, DWORD secs)
{
    volatile DWORD* rtc = MapPage(core, 0x57000000u);
    DWORD           sec;
    if (rtc == NULL) return;
    sec                  = FromBcd(rtc[0x70 / 4] & 0x7Fu);
    rtc[0x54 / 4]        = ToBcd((sec + secs) % 60u);
    rtc[0x50 / 4]        = 0x41u;
    Say(L"s3c2410 alarm bcdsec", ToBcd(sec));
    Say(L"s3c2410 alarm almsec", rtc[0x54 / 4]);
    Say(L"s3c2410 alarm rtcalm", rtc[0x50 / 4]);
}

static void ArmPxa255Alarm(HMODULE core, DWORD secs)
{
    volatile DWORD* rtc = MapPage(core, 0x40900000u);
    volatile DWORD* pm  = MapPage(core, 0x40F00000u);
    DWORD           rcnr;
    if (rtc == NULL || pm == NULL) return;
    rcnr    = rtc[0];
    rtc[1]  = rcnr + secs;
    rtc[2]  = (rtc[2] & 0x8u) | 0x4u;
    pm[3]  |= 0x80000000u;
    Say(L"pxa255 alarm rcnr", rcnr);
    Say(L"pxa255 alarm rtar", rtc[1]);
    Say(L"pxa255 alarm rtsr", rtc[2]);
    Say(L"pxa255 alarm pwer", pm[3]);
}

static void ArmVr41xxAlarm(HMODULE core, DWORD secs)
{
    volatile DWORD*          page = MapPage(core, 0x0B000000u);
    volatile unsigned short* rtc;
    DWORD                    low, hi, cmp_low, cmp_hi;
    if (page == NULL) return;
    rtc     = (volatile unsigned short*)((volatile unsigned char*)page + 0xC0u);
    low     = (DWORD)rtc[0] | ((DWORD)rtc[1] << 16);
    hi      = rtc[2];
    cmp_low = low + secs * 32768u;
    cmp_hi  = hi + (cmp_low < low ? 1u : 0u);
    rtc[4]  = (unsigned short)(cmp_low & 0xFFFFu);
    rtc[5]  = (unsigned short)(cmp_low >> 16);
    rtc[6]  = (unsigned short)(cmp_hi & 0xFFFFu);
    Say(L"vr41xx alarm etime", low);
    Say(L"vr41xx alarm ecmp", cmp_low);
}

static DWORD ParseNumber(const WCHAR** pp)
{
    DWORD        v = 0;
    const WCHAR* p = *pp;
    while (*p == L' ') ++p;
    for (; *p >= L'0' && *p <= L'9'; ++p) v = v * 10u + (DWORD)(*p - L'0');
    *pp = p;
    return v;
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrev, LPWSTR lpCmdLine, int nShow)
{
    HMODULE            core  = LoadLibraryW(L"coredll.dll");
    PFN_PowerOffSystem off   = NULL;
    const WCHAR*       p     = lpCmdLine;
    DWORD              ms;
    DWORD              alarm;
    DWORD              soc;

    (void)hInstance; (void)hPrev; (void)nShow;
    if (core != NULL) {
        s_ods = (PFN_OutputDebugStringW)GetProcAddressW(core, L"OutputDebugStringW");
        off   = (PFN_PowerOffSystem)GetProcAddressW(core, L"PowerOffSystem");
    }
    if (p == NULL) p = L"";
    ms    = ParseNumber(&p);
    alarm = ParseNumber(&p);
    soc   = ParseNumber(&p);
    Say(L"sleeping ms", ms);
    Sleep(ms);
    if (alarm != 0 && core != NULL) {
        if (soc == 1u) ArmSa11xxAlarm(core, alarm);
        if (soc == 2u) ArmS3c2410Alarm(core, alarm);
        if (soc == 3u) ArmPxa255Alarm(core, alarm);
        if (soc == 4u) ArmVr41xxAlarm(core, alarm);
    }
    if (off == NULL) {
        Say(L"no PowerOffSystem", 0);
        return 1;
    }
    Say(L"PowerOffSystem at tick", GetTickCount());
    off();
    Say(L"resumed at tick", GetTickCount());
    return 0;
}
