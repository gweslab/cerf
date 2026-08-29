#include "../../kernel_debug_sink.h"
#include "../../trace_manager.h"
#include "../../../core/cerf_emulator.h"
#include "bundle.h"

#include <string>

namespace {

/* CE 2.11 kernel per-char debug writer sub_8005B57C (R0 = char) - the byte sink
   of OEMWriteDebugString (sub_8005B768). Reassemble into lines. */
class Jornada820KernelDbgOutput : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kJornada820BundleCrc32, [this] {
            emu_.Get<TraceManager>().OnPc(0x8005B57Cu,
                [this, line = std::string{}](const TraceContext& c) mutable {
                    emu_.Get<KernelDebugSink>().EmitChar(
                        static_cast<char>(c.regs[0] & 0xFFu), line);
                });
        });
    }
};

}  // namespace

REGISTER_SERVICE(Jornada820KernelDbgOutput);
