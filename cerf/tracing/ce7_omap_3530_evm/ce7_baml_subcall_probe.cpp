#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <cstdint>

#if CERF_DEV_MODE

namespace {

constexpr uint32_t kPcPostBinaryInit       = 0x40452550u;
constexpr uint32_t kPcPostReadStreamHeader = 0x40452560u;
constexpr uint32_t kPcReadBamlStreamExit   = 0x40452570u;

constexpr uint32_t kPcReadObjectEntry      = 0x4045212Cu;
constexpr uint32_t kPcPostObjHdrCreate     = 0x40452168u;
constexpr uint32_t kPcReadObjectExit       = 0x40452290u;

constexpr uint32_t kPcReadObjHdrEntry      = 0x40450818u;
constexpr uint32_t kPcPostReadTypeFlags    = 0x4045088Cu;
constexpr uint32_t kPcPostBinaryRead_case24 = 0x404509F4u;
constexpr uint32_t kPcPostCreateNativeObj   = 0x40450A0Cu;

constexpr uint32_t kPcCreateNativeObjEntry  = 0x40357F74u;
constexpr uint32_t kPcPostGetFactory        = 0x40357FB0u;
constexpr uint32_t kPcPostCreateNativePeer  = 0x40357FDCu;
constexpr uint32_t kPcAfterNullPeerCheck    = 0x40357FF0u;

constexpr uint32_t kVaPCurThd              = 0xFFFFC824u;

class TraceCe7BamlSubcallProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            auto user_proc_only = [](const TraceContext& c) -> bool {
                return (c.emu.Get<ArmMmu>()
                            .State()
                            ->translation_table_base.word
                        & 0xFFFFC000u) != 0u;
            };

            auto hook = [&tm, &user_proc_only]
                        (uint32_t pc, const char* tag) {
                tm.OnPcFiltered(pc, user_proc_only,
                    [tag](const TraceContext& c) {
                        static uint32_t n = 0;
                        ++n;
                        if (n > 30 && (n % 100u) != 0u) return;
                        const uint32_t pcurthd =
                            c.ReadVa32(kVaPCurThd).value_or(0u);
                        LOG(Trace,
                            "[bsc] %s #%u pTh=0x%08X R0=0x%08X R4=0x%08X R5=0x%08X\n",
                            tag, n, pcurthd, c.regs[0], c.regs[4], c.regs[5]);
                    });
            };

            hook(kPcPostBinaryInit,       "post-BinaryReader::Init");
            hook(kPcPostReadStreamHeader, "post-ReadStreamHeader");
            hook(kPcReadBamlStreamExit,   "ReadBamlStream EXIT");

            hook(kPcReadObjectEntry,      "ReadObject ENTRY");
            hook(kPcPostObjHdrCreate,     "post-ReadObjectHeaderAndCreateObject");
            hook(kPcReadObjectExit,       "ReadObject EXIT");
            hook(kPcPostBinaryRead_case24, "post-BinaryReader::Read(case24)");
            hook(kPcPostCreateNativeObj,   "post-CreateNativeObject");

            tm.OnPcFiltered(kPcCreateNativeObjEntry, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[bsc] CreateNativeObject ENTRY #%u pTh=0x%08X "
                        "uiCustomTypeId=0x%08X pCoreServices=0x%08X ppNewObject=0x%08X\n",
                        n, pcurthd, c.regs[0], c.regs[1], c.regs[2]);
                });

            hook(kPcPostGetFactory,       "post-GetNativeObjectFactory");
            hook(kPcPostCreateNativePeer, "post-CreateNativePeer");
            hook(kPcAfterNullPeerCheck,   "AFTER pPeer-NULL check (E_UNEXPECTED path)");

            tm.OnPcFiltered(kPcReadObjHdrEntry, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    const uint32_t this_va = c.regs[0];
                    uint32_t br[4];
                    for (int i = 0; i < 4; ++i)
                        br[i] = c.ReadVa32(this_va + i * 4u).value_or(0xDEAD0001u);
                    LOG(Trace,
                        "[bsc] ReadObjHdrAndCreate ENTRY #%u this=0x%08X "
                        "ppObject=0x%08X pObjAlreadyRead=0x%08X "
                        "binReader: +00=0x%08X +04=0x%08X +08=0x%08X +0C=0x%08X "
                        "+1C(refArr)=0x%08X +20(refSize)=0x%08X\n",
                        n, this_va, c.regs[1], c.regs[2],
                        br[0], br[1], br[2], br[3],
                        c.ReadVa32(this_va + 0x1Cu).value_or(0xDEAD0001u),
                        c.ReadVa32(this_va + 0x20u).value_or(0xDEAD0001u));
                });

            /* Post-ReadTypeAndFlags: R0 = HRESULT, the dependencyObjectIndex
               (BAML type) is at SP+0x2C (sp[0x58+dependencyObjectIndex] in IDA).
               Capture R4 = HRESULT (MOVS R4, R0 just happened). */
            tm.OnPcFiltered(kPcPostReadTypeFlags, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const uint32_t type_at_sp =
                        c.ReadVa32(c.regs[13] + 0x2Cu).value_or(0xDEAD0001u);
                    const uint32_t flags_at_sp =
                        c.ReadVa32(c.regs[13] + 0x24u).value_or(0xDEAD0001u);
                    LOG(Trace,
                        "[bsc] post-ReadTypeAndFlags(in ObjHdr) #%u pTh=0x%08X "
                        "R0(ret)=0x%08X type=0x%08X flags=0x%08X\n",
                        n, pcurthd, c.regs[0], type_at_sp, flags_at_sp);
                });
        });
    }
};

REGISTER_SERVICE(TraceCe7BamlSubcallProbe);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
