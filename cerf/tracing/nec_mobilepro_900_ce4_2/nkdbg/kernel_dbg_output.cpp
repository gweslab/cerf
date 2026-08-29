#include "../../kernel_debug_sink.h"
#include "../../trace_manager.h"
#include "../../../core/cerf_emulator.h"
#include "bundle.h"

#include <string>

namespace {

/* nk.exe sub_90205054 is the OEM debug char-sink (OEMWriteDebugString level),
   nulled by the NEC OAL (= nullsub_3), so all kernel/device.exe/gwes debug
   output is discarded. Hook it (R0 = char) and reassemble lines. */
class NecMobilePro900KernelDbgOutput : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kNecMobilePro900Ce42BundleCrc32, [this] {
            emu_.Get<TraceManager>().OnPc(0x90205054u,
                [this, line = std::string{}](const TraceContext& c) mutable {
                    emu_.Get<KernelDebugSink>().EmitChar(
                        static_cast<char>(c.regs[0] & 0xFFu), line);
                });
        });
    }
};

}  // namespace

REGISTER_SERVICE(NecMobilePro900KernelDbgOutput);
