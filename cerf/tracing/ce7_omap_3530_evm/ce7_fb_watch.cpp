#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "ce7_bundle.h"

namespace {

class TraceCe7FbWatch : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            tm.OnRunLoopIter([](const TraceContext& c) {
                static uint32_t tick = 0;
                static bool printed_primary = false;
                static bool printed_back = false;
                ++tick;
                if ((tick % 2000u) != 0u) return;
                auto& mem = c.emu.Get<EmulatedMemory>();
                /* Scan the entire 16 MB display heap PA range
                   (0x84800000-0x85800000) for any non-zero byte. */
                for (uint32_t base = 0x84800000u; base < 0x85800000u; base += 0x96000u) {
                    const uint8_t* fb = mem.TryTranslate(base);
                    if (!fb) continue;
                    for (uint32_t off = 0; off < 0x96000u; off += 256) {
                        if (fb[off] != 0) {
                            const bool is_primary = (base == 0x84800000u);
                            if (is_primary && !printed_primary) {
                                printed_primary = true;
                                LOG(Trace, "[fbw tick=%u] *** PRIMARY PA 0x84800000 "
                                    "FIRST CONTENT at +0x%X val=0x%02X ***\n",
                                    tick, off, fb[off]);
                            } else if (!is_primary && !printed_back) {
                                printed_back = true;
                                LOG(Trace, "[fbw tick=%u] non-primary PA 0x%08X "
                                    "first content at +0x%X val=0x%02X\n",
                                    tick, base, off, fb[off]);
                            }
                            break;
                        }
                    }
                    if (printed_primary) return;
                }
            });
        });
    }
};

REGISTER_SERVICE(TraceCe7FbWatch);

}  /* namespace */
