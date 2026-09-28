#pragma once

#include <windows.h>
#include <pkfuncs.h>
#include <winddi.h>
#include "include/cerf_gpe.h"
#include "cerf/peripherals/cerf_virt/cerf_virt_blt_descriptor.h"
#include "cerf/peripherals/cerf_virt/cerf_virt_line_descriptor.h"

struct CerfStageWb { BOOL active; ULONG dst_va; void* arena_ptr; ULONG span; };

extern "C" GPE*  GetGPE(void);
extern "C" void  CerfSetVidBackingByOsMajor(unsigned long os_major);
extern "C" void  CerfGetVideoMem(unsigned long* base, unsigned long* size,
                                 unsigned long* freeBytes);
extern "C" void  CerfGetVideoRegion(unsigned long* base, unsigned long* size);
extern "C" BOOL  CerfDDSurfFbInfo(void* lcl, ULONG* pa, int* stride, int* bpp, int* height);
extern "C" unsigned long CerfDDGPESurfBufferVa(unsigned long surf);
extern "C" void  CerfFillSurfaceFromSurfobj(CerfVirt::CerfBltSurface* s, SURFOBJ* pso,
                                            int y0, int y1, CerfStageWb* wb);
extern "C" int   CerfDDrawBlt(void* dstLcl, void* srcLcl, const RECTL* rDest,
                              const RECTL* rSrc, unsigned long ddFlags,
                              unsigned long ropArg, unsigned long fillColor,
                              unsigned long srcKeyOverride);

struct CerfBltBand {
    int dl, dt, dr;
    int sl, st, sr;
    int ml, mt, mr;
    int height, width, src_h;
    int bw, bh, brush_t;
    int dst_stride, dst_bits;
    int src_stride, src_bits;
    int mask_stride, mask_bits;
    int brush_stride, brush_bits;
    bool has_src, has_mask, has_brush, src_pal, use_lut_y;
    bool dst_fb, src_fb, brush_banded;
};

int  CerfBrushRowAt(const CerfBltBand& b, int row);
void CerfBrushBandRows(const CerfBltBand& b, int r0, int r1, int* by0, int* by1);
int  CerfBrushClampEnd(const CerfBltBand& b, int r0, int r1);
int  CerfBrushClampStart(const CerfBltBand& b, int r0, int r1);

enum CerfBandOrder { kCerfBandDown, kCerfBandUp };

enum CerfAliasKind { kCerfAliasNone, kCerfAliasGrid, kCerfAliasOpaque };

ULONG CerfSpanBytes(int x0, int y0, int x1, int y1, int stride, int bits);
int   CerfSrcDyAt(int dst_len, int src_len, int k);
void  CerfClampWindow(int* x0, int* y0, int* x1, int* y1, const RECTL* bound);
ULONG CerfBandSpanBytes(const CerfBltBand& b, int cl, int cr, int r0, int r1);
bool  CerfBandClip(const CerfBltBand& b, GPEBltParms* p, int* cl, int* cr);
int   CerfBandEnd(const CerfBltBand& b, int cl, int cr, ULONG budget, int r0);
int   CerfBandStart(const CerfBltBand& b, int cl, int cr, ULONG budget, int r1);

inline bool CerfConvertibleFmt(EGPEFormat f) {
    return f == gpe1Bpp  || f == gpe2Bpp  || f == gpe4Bpp || f == gpe8Bpp ||
           f == gpe16Bpp || f == gpe24Bpp || f == gpe32Bpp;
}

inline int CerfFormatBpp(EGPEFormat fmt) {
    switch (fmt) {
        case gpe1Bpp:  return 1;
        case gpe2Bpp:  return 2;
        case gpe4Bpp:  return 4;
        case gpe8Bpp:  return 8;
        case gpe16Bpp: return 16;
        case gpe24Bpp: return 24;
        case gpe32Bpp: return 32;
        default:       return 32;
    }
}

enum CerfVidBacking { kCerfVidHeapByPa, kCerfVidHeapMapped };

class CerfDDGPE : public DDGPE {
public:
    CerfDDGPE();

    void SetVidBacking(CerfVidBacking b) { m_vidBacking = b; }

    bool EnsureVideoHeap();
    void GetVirtualVideoMemory(unsigned long* base, unsigned long* size,
                               unsigned long* freeBytes);
    void GetVideoRegion(unsigned long* base, unsigned long* size);
    bool SurfaceFbPa(GPESurf* s, ULONG* pa);
    CerfAliasKind BltAliasKind(GPEBltParms* p);
    BOOL  SnapshotSource(GPEBltParms* p, GPESurf** ppTemp);
    SCODE PlanAliasedBlt(GPEBltParms* p, CerfBandOrder* order, GPESurf** ppTemp);
    SCODE ApplyFbMode();

    virtual SCODE BltPrepare(GPEBltParms* p);
    static void RectToDesc(CerfVirt::CerfBltRect* r, const RECTL* s);
    void FillSurface(CerfVirt::CerfBltSurface* s, GPESurf* surf,
                     int x0, int y0, int x1, int y1, bool host_writes,
                     bool read_palette = true, CerfStageWb* wb = NULL);
    void FillSurfaceFromSurfobj(CerfVirt::CerfBltSurface* s, SURFOBJ* pso,
                                int y0, int y1, CerfStageWb* wb = NULL);
    SCODE HwBlt(GPEBltParms* p);
    SCODE HostLine(GPELineParms* p);

    virtual SCODE BltComplete(GPEBltParms* p);
    virtual SCODE Line(GPELineParms* pLineParms, EGPEPhase phase);
    virtual SCODE AllocSurface(GPESurf** ppSurf, int width, int height,
                               EGPEFormat format, int surfaceFlags);
    virtual void SetVisibleSurface(GPESurf* pSurf, BOOL bWaitForVBlank = FALSE);
    virtual SCODE SetPointerShape(GPESurf* pMask, GPESurf*, int xHot, int yHot,
                                  int cx, int cy);
    virtual SCODE MovePointer(int, int);
    virtual SCODE SetPalette(const PALETTEENTRY* src, unsigned short firstEntry,
                             unsigned short numEntries);
    virtual SCODE GetPalette(PALETTEENTRY** ppPalette, unsigned short* pcEntries);
    virtual SCODE GetModeInfo(GPEMode* pMode, int modeNo);
    virtual int NumModes();
    virtual SCODE SetMode(int modeId, HPALETTE* pPalette);
    virtual int InVBlank();
    virtual ULONG GetGraphicsCaps();
    virtual ULONG DrvEscape(SURFOBJ* pso, ULONG iEsc, ULONG cjIn, PVOID pvIn,
                            ULONG cjOut, PVOID pvOut);
    virtual BOOL IsPaletteSettable();
    virtual BOOL GetScreenDimensions(GPEScreenProps* pProps);
    virtual ULONG* GetClearTypeRGBMasks();

private:
    GPEMode         m_gpeMode;
    unsigned short  m_paletteEntries;
    PALETTEENTRY    m_palette[256];
    SurfaceHeap*    m_pVidHeap;
    BYTE*           m_fbRegionVa;
    BYTE*           m_vidBaseVa;
    ULONG           m_vidSize;
    CerfVidBacking  m_vidBacking;
    int             m_currentRotation;
    void EmitBltBand(const CerfBltBand& b, GPEBltParms* p, int r0, int r1);
    void EmitBltBands(const CerfBltBand& b, GPEBltParms* p, ULONG budget,
                      CerfBandOrder order);
    void EmitBltBandsUp(const CerfBltBand& b, GPEBltParms* p, ULONG budget,
                        int cl, int cr);
    void EmitBltBandsDown(const CerfBltBand& b, GPEBltParms* p, ULONG budget,
                          int cl, int cr);
};
