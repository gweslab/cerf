#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "devemu_wm614_bundle.h"

namespace {

/* #70: imgfs->FAL boundary sub_8823FDA4 (IDA 0x8823FDA4 -> exec 0x03E80DA4).
   Logs each FAL read's sector (a4>>a1[24]) and resolves the runtime FAL fn ptr
   at MEMORY[0x1FF3100] -> module owning the honored-capacity cap. */
constexpr uint32_t kBoundaryPc = 0x03E80DA4u;
constexpr uint32_t kFalFnPtrVa = 0x01FF3100u;
constexpr uint32_t kSig0 = 0xE92D43F0u, kSig1 = 0xE24DD040u,
                   kSig2 = 0xE1B08002u, kSig3 = 0xE3A0E000u;

class TraceWm614FalRead : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kDevemuWm614BundleCrc32, [this, &tm] {
            tm.OnPc(kBoundaryPc, [this](const TraceContext& c) {
                auto& mmu = c.emu.Get<ArmMmu>();
                auto r32 = [&](uint32_t va) -> uint32_t {
                    uint8_t* h = mmu.PeekVaToHost(va);
                    return h ? *reinterpret_cast<uint32_t*>(h) : 0xDEADBEEFu;
                };
                if (r32(kBoundaryPc + 0) != kSig0 ||
                    r32(kBoundaryPc + 4) != kSig1 ||
                    r32(kBoundaryPc + 8) != kSig2 ||
                    r32(kBoundaryPc + 12) != kSig3) return;  /* alias process */
                const uint32_t fal_fn = r32(kFalFnPtrVa);
                if (!fal_dumped_ && fal_fn != 0xDEADBEEFu) {
                    fal_dumped_ = true;
                    LOG(Trace, "[WM614_FAL] FALfn(MEM[1FF3100])=%08X prologue: "
                               "%08X %08X %08X %08X %08X %08X\n", fal_fn,
                        r32(fal_fn), r32(fal_fn + 4), r32(fal_fn + 8),
                        r32(fal_fn + 12), r32(fal_fn + 16), r32(fal_fn + 20));
                }
                /* Dump the previous read's result buffer (filled by now): the
                   decisive zeros-vs-real-bytes datum for our injected .data. */
                if (pending_dest_) {
                    LOG(Trace, "[WM614_FAL]   RESULT @%08X: "
                               "%08X %08X %08X %08X %08X %08X\n",
                        pending_dest_,
                        r32(pending_dest_ +  0), r32(pending_dest_ +  4),
                        r32(pending_dest_ +  8), r32(pending_dest_ + 12),
                        r32(pending_dest_ + 16), r32(pending_dest_ + 20));
                    pending_dest_ = 0;
                }
                const uint32_t off = c.regs[3];
                /* Full injected LA window (baseline injector): mod_hdr 0x2BD9000,
                   .text 0x2BDB000.., .data 0x2BF9000.., .data idx 0x2C07000. */
                if (off < 0x02BD9000u || off >= 0x02C09000u) return;
                pending_dest_ = c.regs[1];
                if (++hits_ > 60) return;
                const uint32_t a1    = c.regs[0];
                const uint32_t size  = c.regs[2];
                const uint32_t shift = r32(a1 + 24 * 4);
                const uint32_t sector = (shift < 32) ? (off >> shift) : 0xFFFFFFFFu;
                LOG(Trace, "[WM614_FAL] #%u off=%08X size=%08X sector=0x%X "
                           "dest=%08X\n", hits_, off, size, sector, c.regs[1]);
            });
        });
    }

private:
    uint32_t hits_ = 0;
    bool     fal_dumped_ = false;
    uint32_t pending_dest_ = 0;
};

REGISTER_SERVICE(TraceWm614FalRead);

}  /* namespace */
