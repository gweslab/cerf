#include <windows.h>
#include <mmsystem.h>

typedef void     (WINAPI *PFN_OutputDebugStringW)(LPCWSTR);
typedef HDC      (WINAPI *PFN_GetDC)(HWND);
typedef int      (WINAPI *PFN_ReleaseDC)(HWND, HDC);
typedef HDC      (WINAPI *PFN_CreateCompatibleDC)(HDC);
typedef HBITMAP  (WINAPI *PFN_CreateCompatibleBitmap)(HDC, int, int);
typedef HGDIOBJ  (WINAPI *PFN_SelectObject)(HDC, HGDIOBJ);
typedef BOOL     (WINAPI *PFN_BitBlt)(HDC, int, int, int, int, HDC, int, int,
                                      DWORD);
typedef BOOL     (WINAPI *PFN_PatBlt)(HDC, int, int, int, int, DWORD);
typedef BOOL     (WINAPI *PFN_DeleteDC)(HDC);
typedef int      (WINAPI *PFN_GetDeviceCaps)(HDC, int);
typedef MMRESULT (WINAPI *PFN_waveOutOpen)(LPHWAVEOUT, UINT, LPCWAVEFORMATEX,
                                           DWORD, DWORD, DWORD);
typedef MMRESULT (WINAPI *PFN_waveOutPrepareHeader)(HWAVEOUT, LPWAVEHDR, UINT);
typedef MMRESULT (WINAPI *PFN_waveOutWrite)(HWAVEOUT, LPWAVEHDR, UINT);

static HMODULE                s_core = NULL;
static PFN_OutputDebugStringW s_ods  = NULL;

static FARPROC Sym(const WCHAR* name) {
    return s_core != NULL ? GetProcAddressW(s_core, name) : NULL;
}

static void ZeroBytes(BYTE* p, DWORD n) {
    DWORD i;
    for (i = 0; i < n; ++i) p[i] = 0;
}

static void Say(const WCHAR* tag, DWORD a, DWORD b) {
    WCHAR buf[96];
    int   n = 0;
    int   i;
    const WCHAR* p;
    if (s_ods == NULL) return;
    for (p = L"cerfstress: "; *p && n < 80; ++p) buf[n++] = *p;
    for (p = tag; *p && n < 80; ++p) buf[n++] = *p;
    buf[n++] = L' ';
    for (i = 28; i >= 0; i -= 4) buf[n++] = L"0123456789ABCDEF"[(a >> i) & 0xFu];
    buf[n++] = L' ';
    for (i = 28; i >= 0; i -= 4) buf[n++] = L"0123456789ABCDEF"[(b >> i) & 0xFu];
    buf[n++] = L'\r';
    buf[n++] = L'\n';
    buf[n]   = 0;
    s_ods(buf);
}

static DWORD WINAPI RenderThread(LPVOID) {
    PFN_GetDC                  getdc  = (PFN_GetDC)Sym(L"GetDC");
    PFN_ReleaseDC              reldc  = (PFN_ReleaseDC)Sym(L"ReleaseDC");
    PFN_CreateCompatibleDC     ccdc   =
        (PFN_CreateCompatibleDC)Sym(L"CreateCompatibleDC");
    PFN_CreateCompatibleBitmap ccbm   =
        (PFN_CreateCompatibleBitmap)Sym(L"CreateCompatibleBitmap");
    PFN_SelectObject           selobj = (PFN_SelectObject)Sym(L"SelectObject");
    PFN_BitBlt                 blt    = (PFN_BitBlt)Sym(L"BitBlt");
    PFN_PatBlt                 pblt   = (PFN_PatBlt)Sym(L"PatBlt");
    PFN_GetDeviceCaps          caps   = (PFN_GetDeviceCaps)Sym(L"GetDeviceCaps");
    PFN_DeleteDC               deldc  = (PFN_DeleteDC)Sym(L"DeleteDC");
    HDC     screen, mem;
    HBITMAP bmp;
    int     w, h;
    DWORD   frame = 0;

    if (!getdc || !reldc || !ccdc || !ccbm || !selobj || !blt || !pblt ||
        !caps || !deldc) {
        Say(L"render no-gdi", 0, 0);
        return 0;
    }
    screen = getdc(NULL);
    if (screen == NULL) { Say(L"render no-dc", 0, 0); return 0; }
    w = caps(screen, HORZRES);
    h = caps(screen, VERTRES);
    if (w <= 0 || h <= 0) {
        Say(L"render no-size", (DWORD)w, (DWORD)h);
        reldc(NULL, screen);
        return 0;
    }
    mem = ccdc(screen);
    bmp = mem != NULL ? ccbm(screen, w, h) : NULL;
    if (mem == NULL || bmp == NULL) {
        Say(L"render no-surface", (DWORD)mem, (DWORD)bmp);
        if (mem != NULL) deldc(mem);
        reldc(NULL, screen);
        return 0;
    }
    selobj(mem, bmp);
    Say(L"render up", (DWORD)w, (DWORD)h);
    for (;;) {
        pblt(mem, 0, 0, w, h, (frame & 1) ? WHITENESS : BLACKNESS);
        pblt(mem, (int)(frame % (DWORD)(w / 2)), 0, w / 2, h, PATINVERT);
        blt(screen, 0, 0, w, h, mem, 0, 0, SRCCOPY);
        blt(mem, 0, 0, w, h, screen, 0, 0, SRCCOPY);
        ++frame;
        if ((frame & 0xFFFu) == 0) Say(L"render frames", frame, GetTickCount());
        Sleep(16);
    }
}

static DWORD WINAPI MemThread(LPVOID) {
    const DWORD kSize = 512u * 1024u;
    BYTE* a = (BYTE*)VirtualAlloc(NULL, kSize, MEM_COMMIT, PAGE_READWRITE);
    BYTE* b = (BYTE*)VirtualAlloc(NULL, kSize, MEM_COMMIT, PAGE_READWRITE);
    DWORD i, sum = 0, pass = 0;
    if (a == NULL || b == NULL) { Say(L"mem no-alloc", 0, 0); return 0; }
    Say(L"mem up", kSize, 0);
    for (;;) {
        const BYTE fill = (BYTE)(sum & 0xFFu);
        for (i = 0; i < kSize; ++i) a[i] = fill;
        for (i = 0; i < kSize; ++i) b[i] = a[i];
        for (i = 0; i < kSize; i += 64u) sum += b[i];
        ++pass;
        if ((pass & 0x3Fu) == 0) Say(L"mem passes", pass, GetTickCount());
        Sleep(5);
    }
}

#define CERF_AUDIO_HDRS 4

static DWORD WINAPI AudioThread(LPVOID) {
    PFN_waveOutOpen          wopen = (PFN_waveOutOpen)Sym(L"waveOutOpen");
    PFN_waveOutPrepareHeader wprep =
        (PFN_waveOutPrepareHeader)Sym(L"waveOutPrepareHeader");
    PFN_waveOutWrite         wwr   = (PFN_waveOutWrite)Sym(L"waveOutWrite");
    const DWORD  kRate  = 11025u;
    const DWORD  kCount = 4410u;
    HWAVEOUT     hwo = NULL;
    WAVEFORMATEX wf;
    WAVEHDR      hdrs[CERF_AUDIO_HDRS];
    short*       buf;
    DWORD        i, blk = 0, queued = 0;
    MMRESULT     rc;

    if (!wopen || !wprep || !wwr) { Say(L"audio no-api", 0, 0); return 0; }
    buf = (short*)VirtualAlloc(NULL, kCount * sizeof(short), MEM_COMMIT,
                               PAGE_READWRITE);
    if (buf == NULL) { Say(L"audio no-alloc", 0, 0); return 0; }
    for (i = 0; i < kCount; ++i) {
        buf[i] = (short)(((i / 12u) & 1u) ? 8000 : -8000);
    }
    ZeroBytes((BYTE*)&wf, sizeof(wf));
    wf.wFormatTag      = WAVE_FORMAT_PCM;
    wf.nChannels       = 1;
    wf.nSamplesPerSec  = kRate;
    wf.wBitsPerSample  = 16;
    wf.nBlockAlign     = 2;
    wf.nAvgBytesPerSec = kRate * 2u;
    for (;;) {
        rc = wopen(&hwo, WAVE_MAPPER, &wf, 0, 0, CALLBACK_NULL);
        Say(L"audio open rc", rc, 0);
        if (rc == MMSYSERR_NOERROR) break;
        Sleep(2000);
    }
    for (i = 0; i < CERF_AUDIO_HDRS; ++i) {
        ZeroBytes((BYTE*)&hdrs[i], sizeof(WAVEHDR));
        hdrs[i].lpData         = (LPSTR)buf;
        hdrs[i].dwBufferLength = kCount * sizeof(short);
        wprep(hwo, &hdrs[i], sizeof(WAVEHDR));
    }
    for (;;) {
        for (i = 0; i < CERF_AUDIO_HDRS; ++i) {
            if (hdrs[i].dwFlags & WHDR_INQUEUE) continue;
            hdrs[i].dwFlags &= ~WHDR_DONE;
            if (wwr(hwo, &hdrs[i], sizeof(WAVEHDR)) != MMSYSERR_NOERROR) {
                continue;
            }
            ++blk;
            ++queued;
        }
        if ((blk & 0xFu) == 0 && blk != 0 && queued != 0) {
            Say(L"audio blocks", blk, GetTickCount());
            queued = 0;
        }
        Sleep(20);
    }
}

static DWORD WINAPI TimerChurnThread(LPVOID) {
    DWORD p = 1, n = 0;
    for (;;) {
        Sleep(p);
        p = (p >= 16u) ? 1u : p + 1u;
        if ((++n & 0x3FFu) == 0) Say(L"timer wakes", n, GetTickCount());
    }
}

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPWSTR lpCmdLine, int) {
    DWORD  level = 2;
    HANDLE t;

    s_core = LoadLibraryW(L"coredll.dll");
    s_ods  = (PFN_OutputDebugStringW)Sym(L"OutputDebugStringW");

    if (lpCmdLine != NULL && lpCmdLine[0] >= L'0' && lpCmdLine[0] <= L'9') {
        level = (DWORD)(lpCmdLine[0] - L'0');
    }
    Say(L"start level", level, GetTickCount());
    if (level == 0) return 0;

    t = CreateThread(NULL, 0, RenderThread, NULL, 0, NULL);
    Say(L"render thread", (DWORD)t, 0);
    if (t != NULL) CloseHandle(t);
    t = CreateThread(NULL, 0, MemThread, NULL, 0, NULL);
    Say(L"mem thread", (DWORD)t, 0);
    if (t != NULL) CloseHandle(t);
    t = CreateThread(NULL, 0, TimerChurnThread, NULL, 0, NULL);
    Say(L"timer thread", (DWORD)t, 0);
    if (t != NULL) CloseHandle(t);
    if (level >= 2u) {
        t = CreateThread(NULL, 0, AudioThread, NULL, 0, NULL);
        Say(L"audio thread", (DWORD)t, 0);
        if (t != NULL) CloseHandle(t);
    }
    for (;;) Sleep(1000);
}
