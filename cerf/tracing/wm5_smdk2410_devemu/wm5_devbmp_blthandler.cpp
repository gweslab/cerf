#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "wm5_bundle.h"

#include <atomic>
#include <cstdint>

namespace {

/* gwes.exe sub_63788 = device-bitmap blt-handler selector: a2(bitmap fmt) vs
   *(a1+168)(device native fmt) decides driver vs engine-SW handler. Unfiltered
   OnPc is sound here: the VA is gwes-only code and the handler discards any fire
   whose fmt fields aren't valid BMF indices (non-gwes alias => garbage r0). */
class TraceWm5DevBmpBltHandler : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kWm5BundleCrc32, [&] {
            tm.OnPc(0x0004E638u, [this](const TraceContext& c) { OnCreate(c); });
            tm.OnPc(0x00063788u, [this](const TraceContext& c) { OnSel(c); });
            tm.OnPc(0x0005A140u, [this](const TraceContext& c) { OnHookSel(c); });
        });
    }

private:
    /* sub_4E638 entry __fastcall(a1=DC, a2=w, a3=h): confirms the CreateBitmap
       path fires and shows bitmap dims. */
    void OnCreate(const TraceContext& c) {
        const uint32_t w = c.regs[1], h = c.regs[2];
        if (w == 0u || h == 0u || w > 4096u || h > 4096u) return;
        if (cCreate_.fetch_add(1, std::memory_order_relaxed) >= 200u) return;
        LOG(Trace, "[BMPCREATE] dc=%08X w=%u h=%u lr=%08X\n", c.regs[0], w, h, c.regs[14]);
    }

    /* no-hook branch: a2(bitmap fmt) vs *(a1+168)(device native fmt). */
    void OnSel(const TraceContext& c) {
        const uint32_t a1 = c.regs[0];
        const uint32_t a2 = c.regs[1];
        const auto nativeFmt = c.ReadVa32(a1 + 168u);
        if (!nativeFmt) return;
        const uint32_t nf = *nativeFmt;
        if (a2 > 9u || nf > 9u) return;
        if (cSel_.fetch_add(1, std::memory_order_relaxed) >= 200u) return;
        const auto devHandler = c.ReadVa32(a1 + 180u);
        LOG(Trace, "[BLTSEL] PDEV=%08X fmt=%u nativeFmt=%u devHandler=%08X route=%s lr=%08X\n",
            a1, a2, nf, devHandler ? *devHandler : 0xBADBAD00u,
            (a2 == nf) ? "DRIVER" : "ENGINE-SW", c.regs[14]);
    }

    /* hook branch sub_5A140(a1=v14, a2=v13): the path WM5 actually takes if
       a device hook is present. Log raw args + caller to characterize it. */
    void OnHookSel(const TraceContext& c) {
        if (cHook_.fetch_add(1, std::memory_order_relaxed) >= 200u) return;
        LOG(Trace, "[BLTSEL-HOOK] a1=%08X a2=%08X lr=%08X\n",
            c.regs[0], c.regs[1], c.regs[14]);
    }

    std::atomic<uint32_t> cCreate_{0};
    std::atomic<uint32_t> cSel_{0};
    std::atomic<uint32_t> cHook_{0};
};

REGISTER_SERVICE(TraceWm5DevBmpBltHandler);

}  /* namespace */
