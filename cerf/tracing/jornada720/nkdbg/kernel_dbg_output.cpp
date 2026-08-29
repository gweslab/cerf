#include "../../kernel_debug_sink.h"
#include "../../trace_manager.h"
#include "../../../core/cerf_emulator.h"
#include "bundle.h"

#include <string>

namespace {

/* J720 kernel per-char debug writer sub_800762A0 (R0 = char) - the
   OEMWriteDebugString stream. Reassemble into lines. */
class Jornada720KernelDbgOutput : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kBundleCrc32, [this] {
            emu_.Get<TraceManager>().OnPc(0x800762A0u,
                [this, line = std::string{}](const TraceContext& c) mutable {
                    emu_.Get<KernelDebugSink>().EmitChar(
                        static_cast<char>(c.regs[0] & 0xFFu), line);
                });
        });
    }
};

}  // namespace

REGISTER_SERVICE(Jornada720KernelDbgOutput);
