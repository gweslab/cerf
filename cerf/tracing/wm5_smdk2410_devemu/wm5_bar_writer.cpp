#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "wm5_bundle.h"

#include <atomic>
#include <cstdint>

namespace {

/* OnPc on cerf_guest sub_10004790 ENTRY (vbase 0x017C0000 + 0x4790): the DDGPE
   convert pre-pass on the bar-draw path; dumps src(a2)/dst(a3) GPESurf headers to
   expose a mis-shaped surface. Unfiltered is fine: cerf_guest maps only in GWES. */
class TraceWm5BarWriter : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kWm5BundleCrc32, [&] {
            tm.OnPc(0x017C4790u, [this](const TraceContext& c) { OnWriter(c); });
        });
    }

private:
    void OnWriter(const TraceContext& c) {
        if (count_.load(std::memory_order_relaxed) > 24u) return;
        const uint64_t n = ++count_;
        if (n > 24u) return;
        auto rd = [&](uint32_t va) -> uint32_t {
            const auto v = c.ReadVa32(va); return v ? *v : 0xBADBAD00u;
        };
        LOG(Trace, "[BARW] #%llu pc=0x%08X a1=%08X a2(src)=%08X a3(dst)=%08X "
                   "a4=%08X sp=%08X lr=%08X\n",
            (unsigned long long)n, c.pc, c.regs[0], c.regs[1], c.regs[2],
            c.regs[3], c.regs[13], c.regs[14]);
        DumpSurf("src(a2)", c, c.regs[1]);
        DumpSurf("dst(a3)", c, c.regs[2]);
    }

    void DumpSurf(const char* tag, const TraceContext& c, uint32_t s) {
        if (s < 0x10000u) { LOG(Trace, "[BARW]   %s null/low=0x%08X\n", tag, s); return; }
        auto w = [&](uint32_t i) -> uint32_t {
            const auto v = c.ReadVa32(s + i * 4u); return v ? *v : 0xBADBAD00u;
        };
        LOG(Trace, "[BARW]   %s @0x%08X words[0..15]: %08X %08X %08X %08X %08X %08X "
                   "%08X %08X %08X %08X %08X %08X %08X %08X %08X %08X\n",
            tag, s, w(0), w(1), w(2), w(3), w(4), w(5), w(6), w(7),
            w(8), w(9), w(10), w(11), w(12), w(13), w(14), w(15));
    }

    std::atomic<uint64_t> count_{0};
};

REGISTER_SERVICE(TraceWm5BarWriter);

}  /* namespace */
