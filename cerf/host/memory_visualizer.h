#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

#include <cstdint>

/* Read-only viewport over guest physical memory. MUST stay read-only with no
   MMU/TLB side effect: a TLB-filling or slow-path read here shifts JIT IRQ
   delivery timing and manufactures heisenbugs (agent_docs/subsystems.md
   TraceManager note); reads go through EmulatedMemory::TryTranslate only. */
class MemoryVisualizer : public Service {
public:
    using Service::Service;
    ~MemoryVisualizer() override;

    bool ShouldRegister() override;

    enum class Interp { Bit1, Gray8, Rgb565, Rgb8888 };
    enum class Space  { Pa, Va };  /* Va = live on-CPU process via ArmMmu::PeekVaToHost */

    /* UI thread. Fills every pixel of dib_bgra32[0..w*h). */
    void RenderInto(HDC dc, uint32_t* dib_bgra32, uint32_t width, uint32_t height);

    /* UI thread. Consumes mouse/key/wheel for the visualizer tab; returns true
       when the message was handled (caller stops dispatch). Owns its own
       SetCapture/ReleaseCapture via the passed hwnd so the canvas stays thin. */
    bool HandleInput(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp);

    /* Cancel an in-progress drag (canvas calls when switching away). */
    void CancelInput();

private:
    void     OnKeyDown(uint8_t vk);
    bool     JumpToFramebuffer();
    uint32_t BytesPerSample() const;
    void     DrawOverlay(HDC dc, uint32_t width, uint32_t height);
    HFONT    EnsureFont();

    Interp   interp_       = Interp::Rgb565;
    Space    space_        = Space::Pa;
    uint32_t base_pa_      = 0;
    uint32_t base_va_      = 0;
    uint32_t stride_bytes_ = 512;
    int      zoom_         = 0;   /* >0 magnify (zoom_+1 px/sample); <0 minify (skip -zoom_+1) */
    bool     initialized_  = false;

    bool     dragging_     = false;
    int      drag_x_       = 0;
    int      drag_y_       = 0;
    uint32_t drag_base_pa_ = 0;

    HFONT    font_ = nullptr;
};
