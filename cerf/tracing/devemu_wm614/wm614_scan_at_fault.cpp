#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "devemu_wm614_bundle.h"

namespace {

/* #70: imgfs executes only in the process running the FSD, not at the global
   0x8823E000 staging copy. The Data Abort fires in that process (it just ran
   imgfs to load the driver's .data), so scan for the imgfs byte-reader 4-word
   signature from the fault context, where imgfs IS mapped. */
constexpr uint32_t kFaultPc   = 0x022F5040u;
constexpr uint32_t kFaultInsn = 0xE7B13104u;
constexpr uint32_t kSig0 = 0xE92D4FF0u, kSig1 = 0xE24DD010u,
                   kSig2 = 0xE1A08003u, kSig3 = 0xE58D800Cu;

class TraceWm614ScanAtFault : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kDevemuWm614BundleCrc32, [this, &tm] {
            tm.OnPc(kFaultPc, [this](const TraceContext& c) {
                if (done_) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                auto r32 = [&](uint32_t va) -> uint32_t {
                    uint8_t* h = mmu.PeekVaToHost(va);
                    return h ? *reinterpret_cast<uint32_t*>(h) : 0xFFFFFFFFu;
                };
                if (r32(kFaultPc) != kFaultInsn) return;  /* real fault, not alias */
                done_ = true;
                const uint32_t pid = mmu.State()->process_id;
                LOG(Trace, "[WM614_SCAN] at fault pid=%08X — scanning for imgfs\n", pid);
                /* FAL/block read fn ptr imgfs imports at 0x1FF3100 (sub_88244BC8
                   thunks MEMORY[0x1FF3100]); resolve target → which module. */
                for (uint32_t off = 0x100; off <= 0x110; off += 4)
                    LOG(Trace, "[WM614_SCAN] imgfs-import[0x1FF3%03X] = %08X\n",
                        off, r32(0x01FF3000u + off));
                auto scan = [&](uint32_t lo, uint32_t hi, const char* tag) {
                    for (uint32_t va = lo; va < hi; va += 0x1000u) {
                        uint8_t* h = mmu.PeekVaToHost(va);
                        if (!h) continue;
                        const uint32_t* w = reinterpret_cast<const uint32_t*>(h);
                        for (uint32_t i = 0; i + 3 < 1024; ++i) {
                            if (w[i] == kSig0 && w[i+1] == kSig1 &&
                                w[i+2] == kSig2 && w[i+3] == kSig3)
                                LOG(Trace, "[WM614_SCAN] %s imgfs-byteReader@%08X\n",
                                    tag, va + i * 4u);
                        }
                    }
                };
                scan(0x02000000u, 0x04000000u, "slot");
                scan(0x40000000u, 0x42000000u, "dllreg");
                scan(0x80000000u, 0x82000000u, "k80");
                scan(0x88200000u, 0x88260000u, "kstg");
            });
        });
    }

private:
    bool done_ = false;
};

REGISTER_SERVICE(TraceWm614ScanAtFault);

}  /* namespace */
