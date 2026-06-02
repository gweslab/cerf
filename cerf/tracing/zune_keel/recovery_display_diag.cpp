#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"

#include <atomic>
#include <cstring>

#if CERF_DEV_MODE

namespace {

/* recovery.bin bundle CRC (only recovery.bin loads under --recovery). */
constexpr uint32_t kRecoveryCrc32 = 0x824041F7u;

/* zrecover's FCSE process_id, captured when its framebuffer IOCTL reaches the
   kernel handler, used to filter the user-VA hooks inside zrecover's sub_2125C. */
std::atomic<uint32_t> g_zpid{0xFFFFFFFFu};

uint32_t CurPid(const TraceContext& c) {
    return c.emu.Get<ArmMmu>().State()->process_id;
}

/* Watches zrecover's recovery-splash path: the FB-descriptor IOCTL and the
   MmMapIoSpace return inside sub_2125C. */
class RecoveryDisplayDiag : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kRecoveryCrc32, [&] {
            tm.OnPc(0x88241238u, [](const TraceContext& c) {
                g_zpid.store(CurPid(c), std::memory_order_relaxed);
                const uint8_t* a = c.emu.Get<EmulatedMemory>().TryTranslate(0x80000000u);
                if (!a) return;
                uint32_t magic, fbpa, fbsz;
                std::memcpy(&magic, a + 0,    4);
                std::memcpy(&fbpa,  a + 0x60, 4);
                std::memcpy(&fbsz,  a + 0x64, 4);
                LOG(Trace, "[REC] FB IOCTL pid=0x%08X magic=0x%08X fb_pa=0x%08X "
                           "fb_sz=0x%08X\n", g_zpid.load(), magic, fbpa, fbsz);
            });

            auto zpid = [](const TraceContext& c) -> bool {
                return CurPid(c) == g_zpid.load(std::memory_order_relaxed);
            };
            tm.OnPcFiltered(0x212B4u, zpid, [](const TraceContext& c) {
                LOG(Trace, "[REC] MmMapIoSpace -> 0x%08X (%s)\n",
                    c.regs[0], c.regs[0] ? "draws" : "NULL, bails");
            });
        });
    }
};

REGISTER_SERVICE(RecoveryDisplayDiag);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
