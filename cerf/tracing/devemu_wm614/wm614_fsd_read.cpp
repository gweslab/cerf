#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../cpu/emulated_memory.h"
#include "devemu_wm614_bundle.h"

namespace {

/* #70: imgfs builder PATH2 obj+28 store (STR R7,[R4,#0x1C], IDA 0x88242D88 →
   exec 0x03E83D88, rebase -0x843BF000). Fires before the store: R7=loaded buf,
   R4=section obj, R6=total. Fingerprint 0xE584701C rejects aliasing processes. */
constexpr uint32_t kStorePc = 0x03E83D88u;
constexpr uint32_t kFinger  = 0xE584701Cu;
constexpr uint32_t kOurLaLo = 0x02BF0000u;
constexpr uint32_t kOurLaHi = 0x02C08000u;

class TraceWm614Builder : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kDevemuWm614BundleCrc32, [this, &tm] {
            /* One-shot: read the injected sec-idx pages straight from flash PA
               to decide injector-write-bug vs FTL-read-bug. .text idx phys
               PA 0x5FDD000 (works), .data idx phys PA 0x5FCD000 (reads zero). */
            tm.OnRunLoopIter([this](const TraceContext& c) {
                if (flash_done_) return;
                flash_done_ = true;
                auto& mem = c.emu.Get<EmulatedMemory>();
                for (uint32_t i = 0; i < 8; ++i)
                    LOG(Trace, "[WM614_FLASH] .text-idx PA+0x%02X = %08X | "
                               ".data-idx PA+0x%02X = %08X\n",
                        i * 4, mem.ReadWord(0x05FDD000u + i * 4),
                        i * 4, mem.ReadWord(0x05FCD000u + i * 4));
            });
            tm.OnPc(kStorePc, [this](const TraceContext& c) {
                auto& mmu = c.emu.Get<ArmMmu>();
                auto r32 = [&](uint32_t va) -> uint32_t {
                    uint8_t* h = mmu.PeekVaToHost(va);
                    return h ? *reinterpret_cast<uint32_t*>(h) : 0xDEADBEEFu;
                };
                if (r32(kStorePc) != kFinger) return;
                const uint32_t a1  = c.regs[4];
                const uint32_t buf = c.regs[7];
                const uint32_t tot = c.regs[6];
                const uint32_t v7  = r32(a1 + 24);
                const uint32_t roff = ((~r32(v7)) & 0xFFu) == 3 ? 12u
                                    : ((~r32(v7)) & 0xFFu) == 1 ? 44u : 28u;
                const uint32_t la0 = r32(v7 + roff);
                if (la0 < kOurLaLo || la0 >= kOurLaHi) return;
                if (++hits_ > 6) return;
                LOG(Trace, "[WM614_BLD] STORE a1=%08X buf(obj28)=%08X total=%08X "
                           "srcLa=%08X\n", a1, buf, tot, la0);
                if (!vol_done_) {
                    vol_done_ = true;
                    const uint32_t vol = r32(a1 + 4);
                    LOG(Trace, "[WM614_BLD] vol=%08X (looking for total-sector count "
                               "~0x2EA9; max_ls=0x2E88 base=0x2B0)\n", vol);
                    for (uint32_t idx = 160; idx <= 190; ++idx)
                        LOG(Trace, "[WM614_BLD]  vol[%u]@+0x%X = %08X\n",
                            idx, idx * 4, r32(vol + idx * 4));
                }
                for (uint32_t i = 0; i < 16; ++i) {
                    const uint32_t w0 = r32(buf + i * 8);
                    const uint32_t w1 = r32(buf + i * 8 + 4);
                    LOG(Trace, "[WM614_BLD]  LOADED[%u] w0=%08X sz16=%04X la=%08X\n",
                        i, w0, (w0 >> 16) & 0xFFFFu, w1);
                }
            });
        });
    }

private:
    bool     flash_done_ = false;
    bool     vol_done_   = false;
    uint32_t hits_ = 0;
};

REGISTER_SERVICE(TraceWm614Builder);

}  /* namespace */
