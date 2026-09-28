#pragma once

#include <windows.h>
#include <winddi.h>

#ifndef DMDO_0
#define DMDO_0   0
#define DMDO_90  1
#define DMDO_180 2
#define DMDO_270 4
#endif

typedef unsigned long COLOR;
typedef unsigned long ADDRESS;

enum EGPEFormat {
    gpe1Bpp,
    gpe2Bpp,
    gpe4Bpp,
    gpe8Bpp,
    gpe16Bpp,
    gpe24Bpp,
    gpe32Bpp,
    gpe16YCrCb,
    gpeDeviceCompatible,
    gpeUndefined
};

enum EGPEPhase {
    gpeSingle,
    gpePrepare,
    gpeContinue,
    gpeComplete
};

enum EDDGPEPixelFormat {
    ddgpePixelFormat_8bpp,
    ddgpePixelFormat_565,
    ddgpePixelFormat_8880,
    ddgpePixelFormat_8888
};

#define GPE_REQUIRE_VIDEO_MEMORY 0x0001
#define GPE_PREFER_VIDEO_MEMORY  0x0002
#define GPE_BACK_BUFFER          0x0004

class GPE;
class GPESurf;

class ColorConverter {
public:
    ULONG Convert(ULONG value) { return value; }
};

struct GPEMode {
    int        modeId;
    int        width;
    int        height;
    int        Bpp;
    int        frequency;
    EGPEFormat format;
};

struct GPEScreenProps {
    ULONG ulHorzSize;
    ULONG ulVertSize;
    ULONG ulLogPixelsX;
    ULONG ulLogPixelsY;
    ULONG ulAspectX;
    ULONG ulAspectY;
    ULONG ulAspectXY;
};

class GPEFormat {
public:
    GPEFormat() : m_pPalette(0), m_PaletteEntries(0), m_OwnsPalette(0), m_iUniq(0) {}

    ULONG* m_pPalette;
    int    m_PaletteEntries;
    BOOL   m_OwnsPalette;
    ULONG  m_iUniq;
};

int CerfEGPEFormatBpp(EGPEFormat fmt);
int CerfEGPEFormatStride(int width, EGPEFormat fmt);

EGPEFormat CerfIFormatToEGPE(ULONG iFormat);
ULONG      CerfEGPEToIFormat(EGPEFormat fmt);

void CerfRectClamp(RECTL* r, const RECTL* bound);
enum CerfExtentOwner {
    kCerfExtentDstWidth   = 0,
    kCerfExtentDstHeight  = 1,
    kCerfExtentBrushWidth = 2,
    kCerfExtentBrushHeight = 3
};

void CerfRequireExtent(int v, int who);
void CerfEffectiveClip(RECTL* out, const RECTL* clip, GPESurf* dst);

inline EDDGPEPixelFormat CerfFormatToDDGPE(EGPEFormat fmt) {
    switch (fmt) {
        case gpe8Bpp:  return ddgpePixelFormat_8bpp;
        case gpe16Bpp: return ddgpePixelFormat_565;
        case gpe24Bpp: return ddgpePixelFormat_8880;
        case gpe32Bpp: return ddgpePixelFormat_8888;
        default:       return ddgpePixelFormat_8888;
    }
}

class GPESurf {
public:
    GPESurf() {}
    GPESurf(int width, int height, void* pBits, int stride, EGPEFormat format) {
        Init(width, height, pBits, stride, format);
    }
    virtual ~GPESurf();

    void Init(int width, int height, void* pBits, int stride, EGPEFormat format);

    int         Stride()        { return (int)m_nStrideBytes; }
    int         BytesPerPixel() { return m_BytesPixel; }
    EGPEFormat  Format()        { return m_eFormat; }
    GPEFormat*  FormatPtr()     { return &m_Format; }
    void*       Buffer()        { return (void*)m_pVirtAddr; }
    int         Width()         { return m_nWidth; }
    int         Height()        { return m_nHeight; }
    int         InVideoMemory() { return m_fInVideoMemory; }
    ULONG       OffsetInVideoMemory() { return m_nOffsetInVideoMemory; }
    int         IsRotate()      { return m_iRotate != DMDO_0; }
    int         Rotate()        { return m_iRotate; }
    int         ScreenWidth()   { return m_ScreenWidth; }
    int         ScreenHeight()  { return m_ScreenHeight; }

    void SetRotation(int screen_width, int screen_height, int angle) {
        m_ScreenWidth  = screen_width;
        m_ScreenHeight = screen_height;
        m_iRotate      = angle;
    }

    ULONG m_nHandle;

protected:
    ADDRESS    m_pVirtAddr;
    ULONG      m_nStrideBytes;
    GPEFormat  m_Format;
    EGPEFormat m_eFormat;
    int        m_fInVideoMemory;
    BOOL       m_fInUserMemory;
    int        m_nWidth;
    int        m_nHeight;
    ULONG      m_nOffsetInVideoMemory;
    int        m_iRotate;
    int        m_ScreenWidth;
    int        m_ScreenHeight;
    int        m_BytesPixel;
};

class SurfaceHeap {
public:
    SurfaceHeap(ULONG size, ULONG base);
    ~SurfaceHeap();

    SurfaceHeap* Alloc(ULONG bytes);
    void         Free();
    ULONG        Address() const { return m_address; }
    ULONG        Available();

private:
    SurfaceHeap* m_head;
    SurfaceHeap* m_next;
    ULONG        m_address;
    ULONG        m_size;
    int          m_used;
    int          m_isRoot;
};

struct GPEBltParms {
    SCODE (GPE::*pBlt)(GPEBltParms*);
    GPESurf*      pDst;
    GPESurf*      pSrc;
    GPESurf*      pMask;
    GPESurf*      pBrush;
    RECTL*        prclDst;
    RECTL*        prclSrc;
    RECTL*        prclClip;
    COLOR         solidColor;
    ULONG         bltFlags;
    ROP4          rop4;
    RECTL*        prclMask;
    POINTL*       pptlBrush;
    int           xPositive;
    int           yPositive;
    ULONG*        pLookup;
    ULONG (ColorConverter::*pConvert)(ULONG);
    ColorConverter* pColorConverter;
    int           iMode;
    BLENDFUNCTION blendFunction;
    int           toMono;
    COLOR         monoBg;
    RECTL         srcSnapshot;
};

struct GPELineParms {
    SCODE (GPE::*pLine)(GPELineParms*);
    long     xStart;
    long     yStart;
    int      cPels;
    ULONG    dM;
    ULONG    dN;
    long     llGamma;
    int      iDir;
    ULONG    style;
    int      styleState;
    GPESurf* pDst;
    COLOR    solidColor;
    RECTL*   prclClip;
    unsigned short mix;
};

class GPE {
public:
    GPE();
    virtual ~GPE();

    GPESurf* PrimarySurface() { return m_pPrimarySurface; }
    int      ScreenWidth()    { return m_nScreenWidth; }
    int      ScreenHeight()   { return m_nScreenHeight; }
    GPEMode* GetModePtr()     { return m_pMode; }
    int      GetModeId()      { return m_pMode ? m_pMode->modeId : 0; }

    void  SetHSurf(ULONG hsurf) { m_hSurf = hsurf; }
    ULONG GetHSurf()            { return m_hSurf; }

    SCODE BltExpanded(GPESurf* pDst, GPESurf* pSrc, GPESurf* pPattern,
                      const RECT* prclDst, const RECT* prclSrc, ULONG solidColor,
                      ULONG bltFlags, ULONG rop4);

    SCODE EmulatedBlt(GPEBltParms* pParms);
    SCODE EmulatedLine(GPELineParms* pParms);

    virtual SCODE BltPrepare(GPEBltParms* p) = 0;
    virtual SCODE BltComplete(GPEBltParms* p) = 0;
    virtual SCODE Line(GPELineParms* p, EGPEPhase phase) = 0;
    virtual SCODE AllocSurface(GPESurf** ppSurf, int width, int height,
                               EGPEFormat format, int surfaceFlags) = 0;
    virtual SCODE SetMode(int modeId, HPALETTE* pPalette) = 0;
    virtual SCODE GetModeInfo(GPEMode* pMode, int modeNo) = 0;
    virtual int   NumModes() = 0;
    virtual int   InVBlank() = 0;
    virtual SCODE SetPointerShape(GPESurf* pMask, GPESurf* pColor, int xHot, int yHot,
                                  int cx, int cy) = 0;
    virtual SCODE MovePointer(int x, int y) = 0;
    virtual SCODE SetPalette(const PALETTEENTRY* src, unsigned short firstEntry,
                             unsigned short numEntries);
    virtual SCODE GetPalette(PALETTEENTRY** ppPalette, unsigned short* pcEntries);
    virtual void  SetVisibleSurface(GPESurf* pSurf, BOOL bWaitForVBlank = FALSE);
    virtual ULONG GetGraphicsCaps();
    virtual BOOL  IsPaletteSettable();
    virtual BOOL  GetScreenDimensions(GPEScreenProps* pProps);
    virtual ULONG* GetClearTypeRGBMasks();
    virtual ULONG DrvEscape(SURFOBJ* pso, ULONG iEsc, ULONG cjIn, PVOID pvIn,
                            ULONG cjOut, PVOID pvOut);

protected:
    GPESurf* m_pPrimarySurface;
    GPEMode* m_pMode;
    int      m_nScreenWidth;
    int      m_nScreenHeight;
    ULONG    m_hSurf;
};

typedef void* LPDDRAWI_DDRAWSURFACE_LCL;

class DDGPESurf : public GPESurf {
public:
    DDGPESurf(int width, int height, EGPEFormat format);
    DDGPESurf(int width, int height, void* pBits, int stride, EGPEFormat format,
              EDDGPEPixelFormat pf)
        : GPESurf(width, height, pBits, stride, format), m_pixelFormat(pf),
          m_colorKeyLow(0), m_colorKeyHigh(0), m_ownsRemote(0) {}
    virtual ~DDGPESurf();

    EDDGPEPixelFormat PixelFormat() const { return m_pixelFormat; }

    ULONG ColorKeyLow()  const { return m_colorKeyLow; }
    ULONG ColorKeyHigh() const { return m_colorKeyHigh; }
    void  SetColorKey(ULONG low, ULONG high) {
        m_colorKeyLow  = low;
        m_colorKeyHigh = high;
    }

    void SetDDGPESurf(LPDDRAWI_DDRAWSURFACE_LCL lcl);
    static DDGPESurf* GetDDGPESurf(LPDDRAWI_DDRAWSURFACE_LCL lcl);

protected:
    EDDGPEPixelFormat m_pixelFormat;
    ULONG             m_colorKeyLow;
    ULONG             m_colorKeyHigh;
    int               m_ownsRemote;
};

class DDGPE : public GPE {
public:
    DDGPESurf* DDGPEPrimarySurface() { return (DDGPESurf*)m_pPrimarySurface; }
};
