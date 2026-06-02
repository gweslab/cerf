#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "bundle.h"

#include <cstring>

#if CERF_DEV_MODE

namespace {

void ReadAscii(const TraceContext& c, uint32_t va, char* out, int cap) {
    int n = 0;
    for (; n < cap - 1; ++n) {
        auto wc = c.ReadVa16(va + n * 2u);
        if (!wc || *wc == 0) break;
        out[n] = (*wc < 0x80u) ? static_cast<char>(*wc) : '?';
    }
    out[n] = 0;
}

/* WarmCheck.exe (Launch25) blocks before SignalStarted(25); decompile narrows
   it to UnitGetSerialNumber (CreateFileW "DSK1:" + DeviceIoControl on the
   DiskOnChip flash) vs the following KernelIoControl(123456). These two
   kernel-shared coredll hooks (arg-filtered, no user-VA aliasing) bound it:
   if CreateFileW("DSK1:") fires but KernelIoControl(123456) never does, the
   DSK1: DiskOnChip flash IOControl is the dead branch. */
class Falcon4220WarmCheckBlock : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kFalcon4220BundleCrc32, [&] {
            tm.OnPc(0x3F8B380u, [](const TraceContext& c) {   /* coredll!CreateFileW */
                char name[64]; ReadAscii(c, c.regs[0], name, 64);
                if (std::strstr(name, "iskOnChip") || std::strstr(name, "DSK") ||
                    std::strstr(name, "reg.1")) {
                    const uint32_t slot = c.emu.Get<ArmMmu>().State()->process_id >> 25;
                    LOG(Trace, "[FALCON] CreateFileW '%s' slot=%u\n", name, slot);
                }
            });
            tm.OnPc(0x3F852D0u, [](const TraceContext& c) {   /* coredll!KernelIoControl */
                const uint32_t slot = c.emu.Get<ArmMmu>().State()->process_id >> 25;
                if (slot == 4u)   /* WarmCheck.exe (Launch25). */
                    LOG(Trace, "[FALCON] KernelIoControl code=0x%08X slot=%u\n",
                        c.regs[0], slot);
            });
            tm.OnPc(0x3F8DAF4u, [](const TraceContext& c) {   /* coredll!CopyFileW */
                char src[64]; ReadAscii(c, c.regs[0], src, 64);
                char dst[64]; ReadAscii(c, c.regs[1], dst, 64);
                const uint32_t slot = c.emu.Get<ArmMmu>().State()->process_id >> 25;
                LOG(Trace, "[FALCON] CopyFileW '%s' -> '%s' slot=%u\n", src, dst, slot);
            });
            tm.OnPc(0x3F8B038u, [](const TraceContext& c) {   /* coredll!RegRestoreFile */
                char name[64]; ReadAscii(c, c.regs[0], name, 64);
                const uint32_t slot = c.emu.Get<ArmMmu>().State()->process_id >> 25;
                LOG(Trace, "[FALCON] RegRestoreFile '%s' slot=%u\n", name, slot);
            });
        });
    }
};

}  /* namespace */

REGISTER_SERVICE(Falcon4220WarmCheckBlock);

#endif  /* CERF_DEV_MODE */
