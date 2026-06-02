#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "devemu_wm614_bundle.h"

namespace {

/* #70 WM6.1 GA Data Abort: cerf_guest faults at this PC reading VA 0x02306000.
   Dump regs to see if base R1 is .data (overrun) or o32[3] (injection bug). */
constexpr uint32_t kFaultPc   = 0x022F5040u;
constexpr uint32_t kFaultInsn = 0xE7B13104u;  /* LDR R3,[R1,R4,LSL#2]! */

class TraceWm614GaDataAbort : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kDevemuWm614BundleCrc32, [&tm] {
            /* WM5->WM6.1 imgfs.dll RVA-match (base 0x8823E000): hook
               sub_3E44AE0 (module-section ReadFile dispatch) @+0x4AE0 and
               sub_3E4574C (byte reader) @+0x574C. If they fire with sane
               values the RVA-match holds; a5=[SP] offset >>28 = section idx. */
            tm.OnPc(0x88242AE0u, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n > 12) return;
                auto a5 = c.ReadVa32(c.regs[13]);
                uint32_t off = a5.value_or(0xFFFFFFFFu);
                LOG(Trace, "[WM614_FSD] ReadFileDispatch#%u secIdx=%u off=0x%08X "
                           "R0=%08X R1=%08X R2=%08X R3=%08X\n",
                    n, off >> 28, off, c.regs[0], c.regs[1], c.regs[2], c.regs[3]);
            });
            tm.OnPc(0x8824374Cu, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n > 16) return;
                auto loaded = c.ReadVa32(c.regs[0] + 28);  /* a1+28 = loaded index */
                LOG(Trace, "[WM614_FSD] ByteRead#%u a1=%08X loadedIdx=%s%08X "
                           "size=%08X off=%08X\n",
                    n, c.regs[0], loaded ? "" : "(unmapped)", loaded.value_or(0),
                    c.regs[2], c.regs[3]);
            });
            tm.OnPcFiltered(
                kFaultPc,
                [](const TraceContext& c) {
                    auto v = c.ReadVa32(kFaultPc);
                    return v.has_value() && *v == kFaultInsn;
                },
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    if (++n > 4) return;
                    if (n == 1) {
                        /* Read sec[1] page0 directly from flash PA (where the
                           injector wrote it) to decide injector-wrote-zeros (A)
                           vs kernel-reads-wrong (B). sec[1] p0 = phys 23772 =
                           PA 0x05FDC000; unk_1001E9A0 at .data off 0x9A0. */
                        auto& mem = c.emu.Get<EmulatedMemory>();
                        for (uint32_t i = 0; i < 8; ++i) {
                            const uint32_t pa = 0x05FDC9A0u + i * 4;
                            LOG(Trace, "[WM614_DA] flashPA[%u]=0x%08X val=%08X\n",
                                i, pa, mem.ReadWord(pa));
                        }
                        /* Compare runtime .data table head + terminator region
                           against on-disk PE to decide corruption vs logic. */
                        const uint32_t head = 0x022F79A0u;  /* unk_1001E9A0 */
                        const uint32_t term = 0x02300BE0u;  /* ~rva 0x27BE0, on-disk term 0x1F000000 @0x27BF4 */
                        for (uint32_t i = 0; i < 16; ++i) {
                            auto v = c.ReadVa32(head + i * 4);
                            LOG(Trace, "[WM614_DA] head[%u] VA=%08X val=%s%08X\n",
                                i, head + i * 4, v ? "" : "(unmapped)",
                                v ? *v : 0);
                        }
                        for (uint32_t i = 0; i < 10; ++i) {
                            auto v = c.ReadVa32(term + i * 4);
                            LOG(Trace, "[WM614_DA] term[%u] VA=%08X val=%s%08X\n",
                                i, term + i * 4, v ? "" : "(unmapped)",
                                v ? *v : 0);
                        }
                    }
                    const uint32_t ea = c.regs[1] + (c.regs[4] << 2);
                    LOG(Trace, "[WM614_DA] fire#%u EA=R1+(R4<<2)=0x%08X "
                               "R1=0x%08X R4=0x%08X\n",
                        n, ea, c.regs[1], c.regs[4]);
                    LOG(Trace, "[WM614_DA]  R0=%08X R1=%08X R2=%08X R3=%08X "
                               "R4=%08X R5=%08X R6=%08X R7=%08X\n",
                        c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        c.regs[4], c.regs[5], c.regs[6], c.regs[7]);
                    LOG(Trace, "[WM614_DA]  R8=%08X R9=%08X R10=%08X R11=%08X "
                               "R12=%08X SP=%08X LR=%08X PC=%08X\n",
                        c.regs[8], c.regs[9], c.regs[10], c.regs[11],
                        c.regs[12], c.regs[13], c.regs[14], c.regs[15]);
                });
        });
    }
};

REGISTER_SERVICE(TraceWm614GaDataAbort);

}  /* namespace */
