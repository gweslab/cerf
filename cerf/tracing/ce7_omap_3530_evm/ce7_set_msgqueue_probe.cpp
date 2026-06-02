#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "ce7_bundle.h"

#include <cstdint>

#if CERF_DEV_MODE

namespace {

constexpr uint32_t kPcSetMsgQueueEntry        = 0xEFDD1888u;
constexpr uint32_t kPcSetMsgQueuePostGetInfo  = 0xEFDD18C0u;
constexpr uint32_t kPcSetMsgQueuePostCbCheck  = 0xEFDD18DCu;
constexpr uint32_t kPcSetMsgQueueStoreQueue   = 0xEFDD18E8u;
constexpr uint32_t kPcSetMsgQueuePostInitSvc  = 0xEFDD18F0u;
constexpr uint32_t kPcSetMsgQueueFailPath     = 0xEFDD18FCu;
constexpr uint32_t kPcSetMsgQueueSuccessExit  = 0xEFDD1910u;
constexpr uint32_t kPcUnregisterCompositorI   = 0xEFDD2544u;

class TraceCe7SetMsgQueueProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            tm.OnPc(kPcSetMsgQueueEntry, [](const TraceContext& c) {
                LOG(Trace,
                    "[smq] SetMessageQueue ENTRY this=0x%08X hWriteMsgQueue=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(kPcSetMsgQueuePostGetInfo, [](const TraceContext& c) {
                LOG(Trace,
                    "[smq] post-GetMsgQueueInfo this=R4=0x%08X hMsgQ=R5=0x%08X "
                    "R0(success)=0x%08X (0=fail,nonzero=ok)\n",
                    c.regs[4], c.regs[5], c.regs[0]);
            });
            tm.OnPc(kPcSetMsgQueuePostCbCheck, [](const TraceContext& c) {
                /* R3 = (cbMaxMessage >= 0x28) ? 1 : 0 by this point. */
                LOG(Trace,
                    "[smq] post-cbMaxMessage-check R3=%u (0=too-small=fail) "
                    "this=R4=0x%08X hMsgQ=R5=0x%08X\n",
                    c.regs[3], c.regs[4], c.regs[5]);
            });
            tm.OnPc(kPcSetMsgQueueStoreQueue, [](const TraceContext& c) {
                LOG(Trace,
                    "[smq] STR R5->[R4] about to set this->m_hNotifyQueue "
                    "this=R4=0x%08X new_queue=R5=0x%08X\n",
                    c.regs[4], c.regs[5]);
            });
            tm.OnPc(kPcSetMsgQueuePostInitSvc, [](const TraceContext& c) {
                LOG(Trace,
                    "[smq] post-InitializeServiceThread this=R4=0x%08X "
                    "R0(result)=0x%08X (nonzero=ok=keep queue, 0=fail=will-reset-to-0)\n",
                    c.regs[4], c.regs[0]);
            });
            tm.OnPc(kPcSetMsgQueueFailPath, [](const TraceContext& c) {
                uint32_t cur_q = c.ReadVa32(c.regs[4]).value_or(0xDEADBEEFu);
                LOG(Trace,
                    "[smq] FAIL-PATH entry — about to clear m_hNotifyQueue "
                    "this=R4=0x%08X current_queue=0x%08X (will become 0)\n",
                    c.regs[4], cur_q);
            });
            tm.OnPc(kPcSetMsgQueueSuccessExit, [](const TraceContext& c) {
                uint32_t final_q = c.ReadVa32(c.regs[4]).value_or(0xDEADBEEFu);
                LOG(Trace,
                    "[smq] SUCCESS-EXIT this=R4=0x%08X m_hNotifyQueue=0x%08X "
                    "R0=0x%08X\n",
                    c.regs[4], final_q, c.regs[0]);
            });
            tm.OnPc(kPcUnregisterCompositorI, [](const TraceContext& c) {
                /* Who tears down the compositor ~19ms after a successful register?
                   At entry LR = caller return addr: 0xEFDD262C => internal GWES
                   (call site 0xEFDD2628); 0xEFDD4C10 => ExternalApiSet::
                   UnregisterCompositor (process-initiated, call site 0xEFDD4C0C). */
                LOG(Trace,
                    "[smq] UnregisterCompositor_I ENTRY this=R0=0x%08X LR(caller)=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
        });
    }
};

REGISTER_SERVICE(TraceCe7SetMsgQueueProbe);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
