#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <cstdint>

#if CERF_DEV_MODE

namespace {

constexpr uint32_t kPcCobtEntry         = 0x4033FD04u;
constexpr uint32_t kPcCobtIndexCompare  = 0x4033FD3Cu;
constexpr uint32_t kPcCobtPostVtblCall  = 0x4033FD78u;
constexpr uint32_t kPcCcoCreateObjEntry = 0x40337218u;
constexpr uint32_t kPcCcoPreMhTypeBlx   = 0x40337290u;
constexpr uint32_t kPcCcoPostMhTypeBlx  = 0x40337298u;
constexpr uint32_t kPcValAndInitEntry   = 0x403160B4u;
constexpr uint32_t kPcPreInitInstance   = 0x403160DCu;
constexpr uint32_t kPcPostInitInstance  = 0x403160E0u;
constexpr uint32_t kPcPreRegDefVal      = 0x403161D4u;
constexpr uint32_t kPcPostRegDefVal     = 0x403161D8u;
constexpr uint32_t kPcValAndInitExit    = 0x40316230u;
constexpr uint32_t kVaPCurThd           = 0xFFFFC824u;

class TraceCe7CreateObjByIdxProbe : public Service {
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

            tm.OnPcFiltered(kPcCobtEntry, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[cobt] ENTRY #%u pTh=0x%08X pContext=0x%08X nIndex=0x%08X object=0x%08X\n",
                        n, pcurthd, c.regs[0], c.regs[1], c.regs[2]);
                });

            tm.OnPcFiltered(kPcCobtIndexCompare, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    LOG(Trace,
                        "[cobt] index-compare #%u nIndex=0x%08X s_cMetaData=0x%08X (in_range=%d)\n",
                        n, c.regs[1], c.regs[3],
                        (c.regs[1] < c.regs[3]) ? 1 : 0);
                });

            tm.OnPcFiltered(kPcCobtPostVtblCall, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    LOG(Trace,
                        "[cobt] post-vtbl[27] #%u R0(ret)=0x%08X R4(fnAddr)=0x%08X\n",
                        n, c.regs[0], c.regs[4]);
                });

            tm.OnPcFiltered(kPcCcoCreateObjEntry, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    const uint32_t pClass = c.regs[1];
                    const uint32_t hType =
                        c.ReadVa32(pClass + 8u).value_or(0xDEAD0001u);
                    uint32_t cls[8];
                    for (int i = 0; i < 8; ++i)
                        cls[i] = c.ReadVa32(pClass + i * 4u).value_or(0xDEAD0001u);
                    LOG(Trace,
                        "[cco-co] CreateObject ENTRY #%u this=0x%08X pClass=0x%08X "
                        "cString=0x%08X pString=0x%08X "
                        "CClassInfo[0..7]={%08X %08X m_hType=%08X %08X %08X %08X %08X %08X}\n",
                        n, c.regs[0], pClass, c.regs[2], c.regs[3],
                        cls[0], cls[1], cls[2], cls[3],
                        cls[4], cls[5], cls[6], cls[7]);
                    (void)hType;
                });

            tm.OnPcFiltered(kPcCcoPreMhTypeBlx, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    LOG(Trace,
                        "[cco-co] pre-BLX m_hType #%u R3(m_hType)=0x%08X R0(&pDO)=0x%08X R1(&cp)=0x%08X\n",
                        n, c.regs[3], c.regs[0], c.regs[1]);
                });

            tm.OnPcFiltered(kPcCcoPostMhTypeBlx, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    LOG(Trace,
                        "[cco-co] post-BLX m_hType #%u R0(ret)=0x%08X\n",
                        n, c.regs[0]);
                });

            tm.OnPcFiltered(kPcValAndInitEntry, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    LOG(Trace,
                        "[vai] ValidateAndInit ENTRY #%u pDO=0x%08X ppDO=0x%08X\n",
                        n, c.regs[0], c.regs[1]);
                });

            tm.OnPcFiltered(kPcPreInitInstance, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    LOG(Trace,
                        "[vai] pre-BLX InitInstance #%u R3(InitInstance fn)=0x%08X R0(pDO)=0x%08X\n",
                        n, c.regs[3], c.regs[0]);
                });

            tm.OnPcFiltered(kPcPostInitInstance, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    LOG(Trace,
                        "[vai] post-BLX InitInstance #%u R0(ret)=0x%08X\n",
                        n, c.regs[0]);
                });

            tm.OnPcFiltered(kPcPreRegDefVal, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    /* full trace — no cap, find the failing prop */
                    LOG(Trace,
                        "[vai] pre-BL RegisterDefaultValueForProperty #%u "
                        "R0(this)=0x%08X R1(pdp)=0x%08X\n",
                        n, c.regs[0], c.regs[1]);
                });

            tm.OnPcFiltered(kPcPostRegDefVal, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    /* full trace — no cap, find the failing prop */
                    LOG(Trace,
                        "[vai] post-BL RegisterDefaultValueForProperty #%u R0(ret)=0x%08X\n",
                        n, c.regs[0]);
                });

            tm.OnPcFiltered(kPcValAndInitExit, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    if (n > 30 && (n % 100u) != 0u) return;
                    LOG(Trace,
                        "[vai] EXIT #%u R0(=R7=v7)=0x%08X\n",
                        n, c.regs[0]);
                });
        });
    }
};

REGISTER_SERVICE(TraceCe7CreateObjByIdxProbe);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
