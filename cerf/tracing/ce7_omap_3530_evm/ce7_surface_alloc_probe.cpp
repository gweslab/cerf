#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "ce7_bundle.h"

namespace {

class TraceCe7SurfaceAllocProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        LOG(Trace, "[alloc-probe-sentinel] OnReady called, registering for bundle 0x%08X\n", kCe7BundleCrc32);
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            LOG(Trace, "[alloc-probe-sentinel] RegisterForBundle lambda executing\n");
            tm.OnPc(0xEF017EC8u, [](const TraceContext& c) {
                LOG(Trace, "[alloc] Heap::Allocate ENTRY this=0x%08X "
                    "size=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });

            tm.OnPc(0xEF0162C8u, [](const TraceContext& c) {
                LOG(Trace, "[alloc] OMAPFlatSurface::Allocate ENTRY this=0x%08X "
                    "fmt=%u W=%u H=%u LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });

            tm.OnPc(0xEF016BB0u, [](const TraceContext& c) {
                LOG(Trace, "[alloc] OMAPFlatSurfaceManager::Allocate ENTRY "
                    "this=0x%08X fmt=%u W=%u H=%u LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });

            tm.OnPc(0xEF016C7Cu, [](const TraceContext& c) {
                LOG(Trace, "[alloc] OMAPFlatSurfaceManager::AllocateGDI ENTRY "
                    "this=0x%08X fmt=%u W=%u H=%u LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });

            tm.OnPc(0xEF00E204u, [](const TraceContext& c) {
                LOG(Trace, "[alloc] OMAPDDGPE::AllocSurface(W,H,fmt,pixfmt,?) "
                    "this=0x%08X W=%u H=%u fmt=0x%X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });

            tm.OnPc(0xEF00EB18u, [](const TraceContext& c) {
                LOG(Trace, "[alloc] OMAPDDGPE::AllocSurface(GPESurf**,W,H,fmt) "
                    "this=0x%08X W=%u H=%u fmt=0x%X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });

            tm.OnPc(0xEF00EC4Cu, [](const TraceContext& c) {
                LOG(Trace, "[alloc] OMAPDDGPE::AllocSurface(OMAP**,pixfmt,W,H) "
                    "this=0x%08X pixfmt=%u W=%u H=%u LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });

            tm.OnPc(0xEF0199E4u, [](const TraceContext& c) {
                LOG(Trace, "[alloc] DrvEnableSurface ENTRY R0=0x%08X "
                    "LR=0x%08X\n", c.regs[0], c.regs[14]);
            });

            tm.OnPc(0xEF017A2Cu, [](const TraceContext& c) {
                LOG(Trace, "[alloc] OMAPVrfbSurfaceManager::Allocate ENTRY "
                    "this=0x%08X fmt=%u W=%u H=%u LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });
            tm.OnPc(0xEF017B10u, [](const TraceContext& c) {
                LOG(Trace, "[alloc] OMAPVrfbSurfaceManager::AllocateGDI ENTRY "
                    "this=0x%08X fmt=%u W=%u H=%u LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });
            tm.OnPc(0xEF017104u, [](const TraceContext& c) {
                LOG(Trace, "[alloc] OMAPVrfbSurface::Allocate ENTRY this=0x%08X "
                    "fmt=%u W=%u H=%u LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });

            tm.OnPc(0xEF017DC4u, [](const TraceContext& c) {
                LOG(Trace, "[alloc] Heap::Heap CTOR this=0x%08X size=0x%08X "
                    "base=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });

            tm.OnPc(0xEF00E910u, [](const TraceContext& c) {
                LOG(Trace, "[alloc] OMAPDDGPESurface::CTOR this=0x%08X "
                    "pSurfMgr=0x%08X pSurface=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });

            tm.OnPc(0xEF00E528u, [](const TraceContext& c) {
                LOG(Trace, "[flip] OMAPDDGPE::FlipSurface this=0x%08X "
                    "pSurf=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEF0383B4u, [](const TraceContext& c) {
                LOG(Trace, "[flip] HalFlip(DDHAL_FLIPDATA*) pd=0x%08X "
                    "LR=0x%08X\n", c.regs[0], c.regs[14]);
            });
            tm.OnPc(0xEF03599Cu, [](const TraceContext& c) {
                LOG(Trace, "[flip] OMAPSGXDDGPE::Flip this=0x%08X "
                    "pSurf=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEF00E494u, [](const TraceContext& c) {
                LOG(Trace, "[flip] OMAPDDGPE::SurfaceFlipping this=0x%08X "
                    "pSurf=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEF018D6Cu, [](const TraceContext& c) {
                LOG(Trace, "[flip] DDGPE::SetVisibleSurface this=0x%08X "
                    "pSurf=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEF018D84u, [](const TraceContext& c) {
                LOG(Trace, "[flip] DDGPE::SetVisibleSurface(GPESurf,H) "
                    "this=0x%08X pSurf=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
        });
    }
};

REGISTER_SERVICE(TraceCe7SurfaceAllocProbe);

}  /* namespace */
