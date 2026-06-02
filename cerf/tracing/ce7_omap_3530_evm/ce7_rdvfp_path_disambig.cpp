#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <cstdint>

#if CERF_DEV_MODE

namespace {

constexpr uint32_t kPcRdvfpEntry           = 0x40377E30u;
constexpr uint32_t kPcRdvfpPath1Bcs        = 0x40377F94u;
constexpr uint32_t kPcRdvfpSwitchDispatch  = 0x40378198u;
constexpr uint32_t kPcRdvfpPath2DefaultMov = 0x403786B4u;
constexpr uint32_t kPcVaiPreIsProperty     = 0x403161B8u;
constexpr uint32_t kPcVaiPostIsProperty    = 0x403161C0u;
constexpr uint32_t kPcRdvfpPreGetValueBlx  = 0x40378044u;
constexpr uint32_t kPcRdvfpPostGetValue    = 0x40378048u;
constexpr uint32_t kPcGvvmcEntry           = 0x40373E90u;
constexpr uint32_t kPcGvvmcPostGetMethod   = 0x40373EB4u;
constexpr uint32_t kPcGvvmcPostMethodCall  = 0x40373ED0u;
constexpr uint32_t kPcContentEntry         = 0x40371914u;
constexpr uint32_t kPcContentPostGetContent = 0x40371968u;
constexpr uint32_t kPcContentAtBfi         = 0x40371978u;
constexpr uint32_t kPcContentPostBfi       = 0x4037197Cu;
constexpr uint32_t kPcContentPostStrPl     = 0x40371984u;
constexpr uint32_t kPcContentReturn        = 0x403719A0u;

constexpr uint32_t kVaPCurThd = 0xFFFFC824u;

uint32_t g_rdvfp_call_n = 0;

class TraceCe7RdvfpPathDisambig : public Service {
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

            tm.OnPcFiltered(kPcRdvfpEntry, user_proc_only,
                [](const TraceContext& c) {
                    ++g_rdvfp_call_n;
                    const uint32_t pdp = c.regs[1];
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const uint32_t pdp_vt = c.ReadVa32(pdp + 0u).value_or(0xDEADBEEFu);
                    const uint32_t pdp_4  = c.ReadVa32(pdp + 4u).value_or(0xDEADBEEFu);
                    const uint32_t pdp_8  = c.ReadVa32(pdp + 8u).value_or(0xDEADBEEFu);
                    const uint32_t pdp_C  = c.ReadVa32(pdp + 0xCu).value_or(0xDEADBEEFu);
                    const uint32_t pdp_20 = c.ReadVa32(pdp + 0x20u).value_or(0xDEADBEEFu);
                    LOG(Trace,
                        "[rdvfp-disamb] ENTRY call_n=%u this=0x%08X "
                        "pdp=0x%08X pClass=0x%08X pTh=0x%08X LR=0x%08X "
                        "pdp[+0]=0x%08X(vtable) pdp[+4]=0x%08X pdp[+8]=0x%08X "
                        "pdp[+C]=0x%08X(m_flags) pdp[+20]=0x%08X(m_cProperty)\n",
                        g_rdvfp_call_n, c.regs[0], pdp, c.regs[2],
                        pcurthd, c.regs[14], pdp_vt, pdp_4, pdp_8, pdp_C, pdp_20);
                });

            tm.OnPcFiltered(kPcVaiPreIsProperty, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    const uint32_t pdp = c.regs[0];
                    const uint32_t fnIsProp = c.regs[3];
                    LOG(Trace,
                        "[rdvfp-disamb] vai-pre-IsProperty #%u pdp=0x%08X "
                        "IsProperty_fn=0x%08X\n",
                        n, pdp, fnIsProp);
                });

            tm.OnPcFiltered(kPcVaiPostIsProperty, user_proc_only,
                [](const TraceContext& c) {
                    static uint32_t n = 0;
                    ++n;
                    LOG(Trace,
                        "[rdvfp-disamb] vai-post-IsProperty #%u ret=0x%08X "
                        "(will %s)\n",
                        n, c.regs[0],
                        c.regs[0] != 0 ? "CALL RDVFP" : "SKIP");
                });

            tm.OnPcFiltered(kPcRdvfpPreGetValueBlx, user_proc_only,
                [](const TraceContext& c) {
                    const uint32_t pdp_vt =
                        c.ReadVa32(c.regs[0]).value_or(0xDEADBEEFu);
                    LOG(Trace,
                        "[rdvfp-disamb] pre-GetValue-BLX call_n=%u "
                        "GetValue_fn=0x%08X this=0x%08X pdp=0x%08X "
                        "this->vtable=0x%08X\n",
                        g_rdvfp_call_n, c.regs[3], c.regs[0], c.regs[1],
                        pdp_vt);
                });

            tm.OnPcFiltered(kPcRdvfpPostGetValue, user_proc_only,
                [](const TraceContext& c) {
                    const uint32_t pValue_lo =
                        c.ReadVa32(c.regs[13]).value_or(0xDEADBEEFu);
                    const uint32_t pValue_hi =
                        c.ReadVa32(c.regs[13] + 4u).value_or(0xDEADBEEFu);
                    LOG(Trace,
                        "[rdvfp-disamb] post-GetValue call_n=%u ret=0x%08X "
                        "pValue.lo=0x%08X pValue.hi=0x%08X\n",
                        g_rdvfp_call_n, c.regs[0], pValue_lo, pValue_hi);
                });

            tm.OnPcFiltered(kPcGvvmcEntry, user_proc_only,
                [](const TraceContext& c) {
                    const uint32_t pdp        = c.regs[1];
                    const uint32_t pdp_24     = c.ReadVa32(pdp + 0x24u).value_or(0xDEADBEEFu);
                    const uint32_t this_pCore = c.ReadVa32(c.regs[0] + 0x18u).value_or(0xDEADBEEFu);
                    const uint32_t pCore_vt   = c.ReadVa32(this_pCore).value_or(0xDEADBEEFu);
                    const uint32_t fnGetPropMethod =
                        c.ReadVa32(pCore_vt + 0x2D8u).value_or(0xDEADBEEFu);
                    LOG(Trace,
                        "[rdvfp-disamb] gvvmc-ENTRY call_n=%u this=0x%08X "
                        "pdp=0x%08X this->m_pCore=0x%08X m_pCore->vtable=0x%08X "
                        "GetPropertyMethodByIndex_fn=0x%08X pdp[+24]=0x%08X(nSharedProps_idx)\n",
                        g_rdvfp_call_n, c.regs[0], pdp,
                        this_pCore, pCore_vt, fnGetPropMethod,
                        pdp_24 & 0xFFFFu);
                });

            tm.OnPcFiltered(kPcGvvmcPostGetMethod, user_proc_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[rdvfp-disamb] gvvmc-post-GetMethod call_n=%u "
                        "R0(method_fn)=0x%08X (NULL=fail/skip, non-NULL=call_method)\n",
                        g_rdvfp_call_n, c.regs[0]);
                });

            tm.OnPcFiltered(kPcGvvmcPostMethodCall, user_proc_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[rdvfp-disamb] gvvmc-post-method-call call_n=%u "
                        "R0(ret)=0x%08X\n",
                        g_rdvfp_call_n, c.regs[0]);
                });

            tm.OnPcFiltered(kPcContentEntry, user_proc_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[rdvfp-disamb] Content-ENTRY call_n=%u this=0x%08X "
                        "cArgs(R1)=%u ppArgs(R2)=0x%08X pResult(R3)=0x%08X\n",
                        g_rdvfp_call_n, c.regs[0], c.regs[1], c.regs[2], c.regs[3]);
                });

            tm.OnPcFiltered(kPcContentPostGetContent, user_proc_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[rdvfp-disamb] Content-post-GetContent call_n=%u "
                        "R0(ret)=0x%08X CPSR=0x%08X N=%u Z=%u "
                        "(PL_taken=%u MI_taken=%u)\n",
                        g_rdvfp_call_n, c.regs[0], c.cpsr,
                        (c.cpsr >> 31) & 1u, (c.cpsr >> 30) & 1u,
                        ((c.cpsr >> 31) & 1u) == 0 ? 1 : 0,
                        ((c.cpsr >> 31) & 1u) == 1 ? 1 : 0);
                });

            tm.OnPcFiltered(kPcContentAtBfi, user_proc_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[rdvfp-disamb] Content-AT-BFI call_n=%u "
                        "R1=0x%08X R3=0x%08X CPSR=0x%08X N=%u "
                        "(pre-execution; PL_taken=%u)\n",
                        g_rdvfp_call_n, c.regs[1], c.regs[3],
                        c.cpsr, (c.cpsr >> 31) & 1u,
                        ((c.cpsr >> 31) & 1u) == 0 ? 1 : 0);
                });

            tm.OnPcFiltered(kPcContentPostBfi, user_proc_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[rdvfp-disamb] Content-post-BFI call_n=%u "
                        "R1=0x%08X R3=0x%08X CPSR=0x%08X N=%u\n",
                        g_rdvfp_call_n, c.regs[1], c.regs[3],
                        c.cpsr, (c.cpsr >> 31) & 1u);
                });

            tm.OnPcFiltered(kPcContentPostStrPl, user_proc_only,
                [](const TraceContext& c) {
                    const uint32_t pValue_lo =
                        c.ReadVa32(c.regs[5]).value_or(0xDEADBEEFu);
                    const uint32_t pValue_hi =
                        c.ReadVa32(c.regs[5] + 4u).value_or(0xDEADBEEFu);
                    LOG(Trace,
                        "[rdvfp-disamb] Content-post-STRPL call_n=%u "
                        "R1=0x%08X R2=0x%08X R3=0x%08X R5(pResult)=0x%08X "
                        "pValue.lo=0x%08X pValue.hi=0x%08X CPSR=0x%08X N=%u\n",
                        g_rdvfp_call_n, c.regs[1], c.regs[2], c.regs[3],
                        c.regs[5], pValue_lo, pValue_hi,
                        c.cpsr, (c.cpsr >> 31) & 1u);
                });

            tm.OnPcFiltered(kPcContentReturn, user_proc_only,
                [](const TraceContext& c) {
                    const uint32_t pValue_lo =
                        c.ReadVa32(c.regs[5]).value_or(0xDEADBEEFu);
                    LOG(Trace,
                        "[rdvfp-disamb] Content-RETURN call_n=%u R0=0x%08X "
                        "pValue.lo(via R5)=0x%08X\n",
                        g_rdvfp_call_n, c.regs[0], pValue_lo);
                });

            tm.OnPcFiltered(kPcRdvfpPath1Bcs, user_proc_only,
                [](const TraceContext& c) {
                    const bool c_set = (c.cpsr & (1u << 29)) != 0u;
                    if (!c_set) return;
                    LOG(Trace,
                        "[rdvfp-disamb] *** PATH 1 (index-OOB) TAKEN *** "
                        "call_n=%u R9(pdp->m_cProperty)=0x%08X "
                        "R3(pClass->m_cProperty)=0x%08X R6(=IsDefault)=0x%08X "
                        "this=0x%08X\n",
                        g_rdvfp_call_n, c.regs[9], c.regs[3], c.regs[6],
                        c.regs[7]);
                });

            tm.OnPcFiltered(kPcRdvfpSwitchDispatch, user_proc_only,
                [](const TraceContext& c) {
                    const uint32_t type_byte = c.regs[3] & 0xFFu;
                    const uint32_t v25       = c.regs[5];
                    const uint32_t pClass    = c.regs[8];
                    const uint32_t v22       = c.regs[9];
                    const uint32_t pValue_lo = c.regs[4];
                    const uint32_t pValue_hi =
                        c.ReadVa32(c.regs[13] + 4u).value_or(0xDEADBEEFu);
                    const uint32_t v26       = c.regs[2];
                    LOG(Trace,
                        "[rdvfp-disamb] switch-dispatch call_n=%u "
                        "type_byte=0x%02X v22=0x%X v25=0x%08X pClass=0x%08X "
                        "pValue.lo=0x%08X pValue.hi=0x%08X v26=0x%X (%s)\n",
                        g_rdvfp_call_n, type_byte, v22, v25, pClass,
                        pValue_lo, pValue_hi, v26,
                        (type_byte == 0u || type_byte > 51u) ? "DEFAULT" : "case");
                });

            tm.OnPcFiltered(kPcRdvfpPath2DefaultMov, user_proc_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[rdvfp-disamb] *** PATH 2 (switch-default) TAKEN *** "
                        "call_n=%u R1(type_byte-1)=0x%08X R3(type_byte)=0x%08X\n",
                        g_rdvfp_call_n, c.regs[1], c.regs[3]);
                });
        });
    }
};

REGISTER_SERVICE(TraceCe7RdvfpPathDisambig);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
