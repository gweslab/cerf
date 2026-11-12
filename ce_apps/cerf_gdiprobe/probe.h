#pragma once

#include <windows.h>

struct ProbeVertex { LONG x; LONG y; USHORT r; USHORT g; USHORT b; USHORT a; };
struct ProbeGradRect { ULONG ul; ULONG lr; };
struct ProbeBlend { BYTE op; BYTE flags; BYTE alpha; BYTE format; };
struct ProbeBmi { BITMAPINFOHEADER h; RGBQUAD c[256]; };

typedef void    (WINAPI *PFN_ODS)(LPCWSTR);
typedef HDC     (WINAPI *PFN_GetDC)(HWND);
typedef HDC     (WINAPI *PFN_CreateCompatibleDC)(HDC);
typedef HGDIOBJ (WINAPI *PFN_SelectObject)(HDC, HGDIOBJ);
typedef BOOL    (WINAPI *PFN_DeleteObject)(HGDIOBJ);
typedef BOOL    (WINAPI *PFN_DeleteDC)(HDC);
typedef HBITMAP (WINAPI *PFN_CreateDIBSection)(HDC, const BITMAPINFO*, UINT, void**, HANDLE,
                                               DWORD);
typedef BOOL    (WINAPI *PFN_BitBlt)(HDC, int, int, int, int, HDC, int, int, DWORD);
typedef BOOL    (WINAPI *PFN_StretchBlt)(HDC, int, int, int, int, HDC, int, int, int, int,
                                         DWORD);
typedef BOOL    (WINAPI *PFN_MaskBlt)(HDC, int, int, int, int, HDC, int, int, HBITMAP, int,
                                      int, DWORD);
typedef BOOL    (WINAPI *PFN_TransparentImage)(HDC, int, int, int, int, HANDLE, int, int, int,
                                               int, COLORREF);
typedef BOOL    (WINAPI *PFN_GradientFill)(HDC, ProbeVertex*, ULONG, PVOID, ULONG, ULONG);
typedef BOOL    (WINAPI *PFN_AlphaBlend)(HDC, int, int, int, int, HDC, int, int, int, int,
                                         ProbeBlend);
typedef HBRUSH  (WINAPI *PFN_CreatePatternBrush)(HBITMAP);
typedef BOOL    (WINAPI *PFN_PatBlt)(HDC, int, int, int, int, DWORD);
typedef BOOL    (WINAPI *PFN_Polyline)(HDC, const POINT*, int);
typedef HBITMAP (WINAPI *PFN_CreateBitmap)(int, int, UINT, UINT, const void*);
typedef int     (WINAPI *PFN_GetDeviceCaps)(HDC, int);

struct ProbeGdi {
    HMODULE                core;
    PFN_ODS                ods;
    PFN_GetDC              getdc;
    PFN_CreateCompatibleDC ccdc;
    PFN_SelectObject       sel;
    PFN_DeleteObject       delobj;
    PFN_DeleteDC           deldc;
    PFN_CreateDIBSection   cdib;
    PFN_BitBlt             blt;
    PFN_StretchBlt         sblt;
    PFN_MaskBlt            mblt;
    PFN_TransparentImage   timg;
    PFN_GradientFill       grad;
    PFN_AlphaBlend         alpha;
    PFN_CreatePatternBrush pbrush;
    PFN_PatBlt             pblt;
    PFN_Polyline           poly;
    PFN_CreateBitmap       cbmp;
    PFN_GetDeviceCaps      caps;
    HDC                    screen;
    HDC                    target;
    int                    target_w;
    int                    target_h;
};

extern ProbeGdi g_probe;

struct ProbeLinear {
    const BYTE* base;
    const BYTE* row0;
    LONG        stride;
    DWORD       size;
};

FARPROC     ProbeSym(const WCHAR* name);
BOOL        ProbeLoadGdi(void);
void        Say(const WCHAR* tag, DWORD a, DWORD b);
void        Done(const WCHAR* tag, BOOL ok);
BYTE        PatternByte(DWORD i);
HBITMAP     MakeDibBits(int w, int h, int bpp, HDC* dc, BYTE** out_bits);
HBITMAP     MakeDib(int w, int h, int bpp, HDC* dc);
void        FreeDib(HBITMAP bmp, HDC dc);
ProbeLinear LinearOf(BYTE* bits, int w, int h, int bpp);

void VerifyOverhang(int height_sign);
void VerifyOverhangScreen(int height_sign);
void OverhangBySourceKind(void);
void SourceOverhang(int bpp, int height_sign);
void MaskOverhang(void);
void ScreenOverhang(void);
void IndexedDestinations(void);
void WideSameSurface(void);
void WideRows(void);
