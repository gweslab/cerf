#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "bundle.h"

#include <atomic>
#include <cstdint>

#if CERF_DEV_MODE

namespace {

class Ppc2000KeybddrProbe : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kPpc2000BundleCrc32, [&] {
            tm.OnPc(0xF43ACCu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 30 || (k & 0xFFu) == 0u) {
                    LOG(Trace, "[PPC2000_KEYPOLL] k=%llu base_R0=0x%08X "
                               "loaded_R3=0x%08X bit0x10=%d\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[3],
                        (c.regs[3] & 0x10) ? 1 : 0);
                }
            });

            /* Track CURTHREAD switches — identify what thread is keybddr's
               StartAddr in PPC2000 (= the equivalent of 8FF66000 in PPC2002). */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_thr{0xCAFEBABEu};
                auto thr = c.ReadVa32(0xFFFFC894u);
                if (!thr) return;
                const uint32_t prev = last_thr.exchange(*thr,
                    std::memory_order_relaxed);
                if (*thr != prev) {
                    LOG(Trace, "[PPC2000_CURTHR] 0x%08X -> 0x%08X\n",
                        prev, *thr);
                }
            });

            /* Identify which thread runs keybddr's StartAddr (PPC2000 entry
               point 0xF441AC). Captures the CURTHREAD value when this PC
               executes. Hook the second instruction (avoid stride conflict). */
            tm.OnPc(0xF441B0u, [](const TraceContext& c) {
                static std::atomic<bool> done{false};
                if (done.load(std::memory_order_relaxed)) return;
                auto cur = c.ReadVa32(0xFFFFC894u);
                if (!cur) return;
                bool exp = false;
                if (!done.compare_exchange_strong(exp, true)) return;
                LOG(Trace, "[PPC2000_KEYBTHR] keybddr_StartAddr thread=0x%08X\n",
                    *cur);
            });

            tm.OnPc(0x80071000u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                wchar_t name[17] = {};
                for (int i = 0; i < 16; ++i) {
                    auto w = c.ReadVa32(c.regs[0] + i * 2);
                    if (!w) break;
                    name[i] = static_cast<wchar_t>(*w & 0xFFFF);
                    if (name[i] == 0) break;
                }
                LOG(Trace, "[PPC2000_CREATE_PROC] k=%llu R0=0x%08X name=%ls "
                           "lr=0x%08X\n",
                    static_cast<unsigned long long>(k),
                    c.regs[0], name, c.regs[14]);
            });

            /* Unfiltered intentional — a process filter would drop every
               CreateThread call in every other process, defeating enumeration. */
            tm.OnPc(0x01FAC45Cu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                auto cur = c.ReadVa32(0xFFFFC894u);
                LOG(Trace, "[PPC2000_CT] k=%llu CURTHR=0x%08X "
                           "R0=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X "
                           "lr=0x%08X\n",
                    static_cast<unsigned long long>(k), cur.value_or(0),
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });

            /* Unfiltered intentional — a process filter would drop every
               CreateProcessW call in every other process. */
            tm.OnPc(0x01FAC3CCu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                auto cur = c.ReadVa32(0xFFFFC894u);
                wchar_t name[17] = {};
                for (int i = 0; i < 16; ++i) {
                    auto w = c.ReadVa32(c.regs[0] + i * 2);
                    if (!w) break;
                    name[i] = static_cast<wchar_t>(*w & 0xFFFF);
                    if (name[i] == 0) break;
                }
                LOG(Trace, "[PPC2000_CPW] k=%llu CURTHR=0x%08X name=%ls "
                           "R0=0x%08X lr=0x%08X\n",
                    static_cast<unsigned long long>(k), cur.value_or(0),
                    name, c.regs[0], c.regs[14]);
            });

            /* Unfiltered intentional — a process filter would drop every
               thread spawn in every other process, defeating enumeration. */
            tm.OnPc(0x01FB10E8u, [](const TraceContext& c) {
                auto cur = c.ReadVa32(0xFFFFC894u);
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                LOG(Trace, "[PPC2000_NEW_THREAD] k=%llu CURTHR=0x%08X "
                           "proc_R0=0x%08X arg_R1=0x%08X\n",
                    static_cast<unsigned long long>(k),
                    cur.value_or(0), c.regs[0], c.regs[1]);
            });
        });
    }
};

}  /* namespace */

REGISTER_SERVICE(Ppc2000KeybddrProbe);

#endif
