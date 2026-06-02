#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "ce7_bundle.h"

#include <cstdint>

namespace {

constexpr uint32_t kPcInvalidateRect_I   = 0xEFD9ADA0u;
constexpr uint32_t kPcInvalidateRgn_I    = 0xEFD9AF60u;
constexpr uint32_t kPcRequestPaint       = 0xEFD6DE60u;
constexpr uint32_t kPcAddPaintRequest    = 0xEFD6DCE8u;
constexpr uint32_t kPcRemovePaintRequest = 0xEFD6C1DCu;
constexpr uint32_t kPcGetPaintMsg        = 0xEFD6C13Cu;
constexpr uint32_t kPcHasPaintRequest    = 0xEFD6C308u;
constexpr uint32_t kPcRepaintProc        = 0xEFD75B80u;
constexpr uint32_t kPcBeginPaint_I       = 0xEFD9A9A4u;
constexpr uint32_t kPcEndPaint_I         = 0xEFD9AD34u;
constexpr uint32_t kPcRecursiveInvalidate     = 0xEFD9D25Cu;
constexpr uint32_t kPcRedrawWindowRecursive   = 0xEFD98BB0u;
constexpr uint32_t kPcCWindowSurfaceInvalidate = 0xEFDD3E28u;
constexpr uint32_t kPcGwesPowerUp              = 0xEFD6A7E8u;
constexpr uint32_t kPcStartupScreenSetup       = 0xEFDA0118u;
constexpr uint32_t kPcStartupScreenFinish      = 0xEFDA01D0u;
constexpr uint32_t kPcGweUserThunkStartupScreenFinish = 0xEFDA2DD8u;
constexpr uint32_t kPcGweUserThunkStartupScreenSetup  = 0xEFDA2D80u;

class TraceCe7PaintPipelineProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            tm.OnPc(kPcInvalidateRect_I, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 60 && (count % 200u) != 0u) return;
                LOG(Trace, "[paint] InvalidateRect_I #%u hwnd=0x%08X lpRect=0x%08X "
                    "bErase=%u LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPc(kPcInvalidateRgn_I, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 60 && (count % 200u) != 0u) return;
                LOG(Trace, "[paint] InvalidateRgn_I #%u hwnd=0x%08X hrgn=0x%08X "
                    "bErase=%u LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPc(kPcRequestPaint, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 60 && (count % 200u) != 0u) return;
                LOG(Trace, "[paint] RequestPaint #%u hwnd=0x%08X fSync=%d LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(kPcAddPaintRequest, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 60 && (count % 200u) != 0u) return;
                const uint32_t mq = c.regs[0];
                const uint32_t hthdOwner =
                    c.ReadVa32(mq + 0x0Cu).value_or(0xDEADBEEFu);
                LOG(Trace, "[paint] MsgQueue::AddPaintRequest #%u this=0x%08X "
                    "hwnd=0x%08X m_hthdOwner=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], hthdOwner, c.regs[14]);
            });
            tm.OnPc(kPcRemovePaintRequest, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 60 && (count % 200u) != 0u) return;
                LOG(Trace, "[paint] MsgQueue::RemovePaintRequest #%u this=0x%08X "
                    "hwnd=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(kPcGetPaintMsg, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 60 && (count % 500u) != 0u) return;
                LOG(Trace, "[paint] MsgQueue::GetPaintMsg #%u this=0x%08X "
                    "hwnd=0x%08X eFlag=0x%X lpMsg=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                    c.regs[14]);
            });
            tm.OnPc(kPcHasPaintRequest, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 60 && (count % 500u) != 0u) return;
                LOG(Trace, "[paint] HasPaintRequest #%u hwnd=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[14]);
            });
            tm.OnPc(kPcRepaintProc, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                LOG(Trace, "[paint] RepaintProc #%u hwnd=0x%08X lParam=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(kPcBeginPaint_I, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                LOG(Trace, "[paint] BeginPaint_I #%u hwnd=0x%08X lpPaint=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(kPcEndPaint_I, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                LOG(Trace, "[paint] EndPaint_I #%u hwnd=0x%08X lpPaint=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(kPcRecursiveInvalidate, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 30 && (count % 200u) != 0u) return;
                LOG(Trace, "[paint] CWindow::RecursiveInvalidate #%u this=0x%08X "
                    "flags=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(kPcRedrawWindowRecursive, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 30 && (count % 200u) != 0u) return;
                LOG(Trace, "[paint] CWindow::RedrawWindowRecursivePaint #%u this=0x%08X "
                    "fForce=%d LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(kPcCWindowSurfaceInvalidate, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 30 && (count % 200u) != 0u) return;
                LOG(Trace, "[paint] CWindowSurface::Invalidate #%u this=0x%08X "
                    "hrgn=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(kPcGwesPowerUp, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                LOG(Trace, "[splash] Gwe::GwesPowerUp #%u fWantsStartupScreen=%u "
                    "LR=0x%08X\n",
                    count, c.regs[0], c.regs[14]);
            });
            tm.OnPc(kPcStartupScreenSetup, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                LOG(Trace, "[splash] StartupScreenSetup #%u fBypass=%u LR=0x%08X\n",
                    count, c.regs[0], c.regs[14]);
            });
            tm.OnPc(kPcStartupScreenFinish, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                LOG(Trace, "[splash] StartupScreenFinish #%u LR=0x%08X\n",
                    count, c.regs[14]);
            });
            tm.OnPc(kPcGweUserThunkStartupScreenSetup, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                LOG(Trace, "[splash] GweUserThunk_StartupScreenSetup #%u "
                    "fBypass=%u LR=0x%08X\n",
                    count, c.regs[0], c.regs[14]);
            });
            tm.OnPc(kPcGweUserThunkStartupScreenFinish, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                LOG(Trace, "[splash] GweUserThunk_StartupScreenFinish #%u "
                    "LR=0x%08X\n",
                    count, c.regs[14]);
            });
        });
    }
};

REGISTER_SERVICE(TraceCe7PaintPipelineProbe);

}  /* namespace */
