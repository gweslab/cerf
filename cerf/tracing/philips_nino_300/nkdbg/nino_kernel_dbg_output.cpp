#include "../../kernel_debug_sink.h"
#include "../../trace_manager.h"
#include "../../../core/cerf_emulator.h"
#include "../../../jit/mips/mips_cpu_state.h"
#include "bundle.h"

#include <string>

namespace {

/* nk.exe sub_9F431FA4 ($a0 = char) is OEMWriteDebugByte. It gates on OEM global
   0x800020A0, the DRAM Bank 1-present flag that sub_9F4117B4 clears on a Nino 300,
   so the byte never reaches the CS3 debug chip: implementing that chip yields no
   output, and only the entry hook recovers the kernel's exception and halt text. */
constexpr uint32_t kOemWriteDebugByte = 0x9F431FA4u;

class NinoKernelDbgOutput : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kBundleCrc32, [this] {
            emu_.Get<TraceManager>().OnPc(kOemWriteDebugByte,
                [this, line = std::string{}](const TraceContext& c) mutable {
                    if (!c.mips) return;
                    emu_.Get<KernelDebugSink>().EmitChar(
                        static_cast<char>(c.mips->gpr[4] & 0xFFu), line);
                });
        });
    }
};

}  // namespace

REGISTER_SERVICE(NinoKernelDbgOutput);
