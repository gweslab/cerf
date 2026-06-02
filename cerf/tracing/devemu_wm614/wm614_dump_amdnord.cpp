#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "devemu_wm614_bundle.h"

#include <fstream>

namespace {

/* #70: dump the decompressed kernel-staging image of amdnord.dll (the IMGFS-
   backing NOR FMD) + its e32/o32 TOC from guest memory, for offline PE
   reconstruction + IDA. Triggered once at the imgfs->FAL boundary (modules
   are loaded by then). amdnord loadVA 0x8826E000..next-mod 0x88276000. */
constexpr uint32_t kFalBoundary = 0x03E80DA4u;
constexpr uint32_t kBSig0 = 0xE92D43F0u, kBSig1 = 0xE24DD040u,
                   kBSig2 = 0xE1B08002u, kBSig3 = 0xE3A0E000u;
constexpr uint32_t kAmdBase = 0x8826E000u, kAmdEnd = 0x88276000u;
constexpr uint32_t kTocBase = 0x880D6238u;  /* amdnord e32; o32 at 0x880D6BF8 */
constexpr uint32_t kTocLen  = 0x200u;

class TraceWm614DumpAmdnord : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kDevemuWm614BundleCrc32, [this, &tm] {
            /* OnPcFiltered, not OnPc: an unfiltered handler is already bound at
               this boundary PC and a 2nd unfiltered OnPc here FATALs on the
               duplicate-registration guard; filtered handlers coexist. */
            tm.OnPcFiltered(
                kFalBoundary,
                [](const TraceContext& c) {
                    auto& mmu = c.emu.Get<ArmMmu>();
                    auto r32 = [&](uint32_t va) -> uint32_t {
                        uint8_t* h = mmu.PeekVaToHost(va);
                        return h ? *reinterpret_cast<uint32_t*>(h) : 0u;
                    };
                    return r32(kFalBoundary + 0) == kBSig0 &&
                           r32(kFalBoundary + 4) == kBSig1 &&
                           r32(kFalBoundary + 8) == kBSig2 &&
                           r32(kFalBoundary + 12) == kBSig3;
                },
                [this](const TraceContext& c) {
                    if (done_) return;
                    done_ = true;
                    auto& mmu = c.emu.Get<ArmMmu>();
                    dump(mmu, kAmdBase, kAmdEnd - kAmdBase,
                         "Z:/tmp/wm614_amdnord.bin");
                    dump(mmu, kTocBase, kTocLen, "Z:/tmp/wm614_amdnord_toc.bin");
                    /* mencfilt (imgfs read callee) + mspart (partition/FAL). */
                    dump(mmu, 0x8824B000u, 0xE000u, "Z:/tmp/wm614_mencfilt.bin");
                    dump(mmu, 0x88259000u, 0x6000u, "Z:/tmp/wm614_mspart.bin");
                    dump(mmu, 0x880D6A78u, 0x100u, "Z:/tmp/wm614_toc_mm.bin");
                });
        });
    }

private:
    static void dump(ArmMmu& mmu, uint32_t va, uint32_t len, const char* path) {
        std::ofstream f(path, std::ios::binary);
        uint32_t wrote = 0;
        for (uint32_t o = 0; o < len; o += 4) {
            uint8_t* h = mmu.PeekVaToHost(va + o);
            uint32_t w = h ? *reinterpret_cast<uint32_t*>(h) : 0u;
            f.write(reinterpret_cast<const char*>(&w), 4);
            if (h) wrote += 4;
        }
        LOG(Trace, "[WM614_DUMP] %s va=%08X len=%08X mapped=%08X\n",
            path, va, len, wrote);
    }

    bool done_ = false;
};

REGISTER_SERVICE(TraceWm614DumpAmdnord);

}  /* namespace */
