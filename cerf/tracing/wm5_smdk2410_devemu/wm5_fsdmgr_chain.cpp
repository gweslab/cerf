#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../boards/page_table_builder.h"
#include "wm5_bundle.h"

namespace {

#define PC_TRACE(addr_, tag_, fmt_)                                   \
    tm.OnPc(addr_, [](const TraceContext& c) {                        \
        LOG(Trace, "[" tag_ "] " fmt_, c.regs[0], c.regs[1],          \
            c.regs[14], c.regs[13]);                                  \
    })

class TraceWm5FsdmgrChain : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kWm5BundleCrc32, [&] {
            /* fsdmgr.Init entry — confirms fsdmgr.dll's Init function
               was actually called. */
            PC_TRACE(0x03F32C90u, "FSDMGR_INIT",
                "fsdmgr!Init entered BootPhase=R0=0x%08X R1=0x%08X LR=0x%08X SP=0x%08X\n");

            /* sub_3F3840C — fsdmgr.Init(0) calls this at LABEL_15. Walks
               AutoLoad registry subkeys, matches BootPhase, LoadLibrary's
               each matching driver DLL. */
            PC_TRACE(0x03F3840Cu, "FSDMGR_ENUM",
                "sub_3F3840C entered phase=R0=0x%08X autoload=R1=0x%08X LR=0x%08X SP=0x%08X\n");
            PC_TRACE(0x03F38A30u, "FSDMGR_WORKER",
                "sub_3F38A30 (worker) entered R0=0x%08X R1=0x%08X LR=0x%08X SP=0x%08X\n");
            PC_TRACE(0x03F41BE8u, "FSDMGR_LOADDRV",
                "sub_3F41BE8 entered R0=0x%08X R1=0x%08X LR=0x%08X SP=0x%08X\n");
            PC_TRACE(0x03F32564u, "FSDMGR_RUNDRV",
                "sub_3F32564 entered R0=0x%08X R1=0x%08X LR=0x%08X SP=0x%08X\n");
            PC_TRACE(0x03F381F0u, "FSDMGR_381F0",
                "sub_3F381F0 entered R0=0x%08X R1=0x%08X LR=0x%08X SP=0x%08X\n");

            /* DriverPath branch helpers (RAMFMD takes this branch):
                 v7 = sub_3F41BA8(2584);   v8 = sub_3F35EB4(v7, name, ...);
                 sub_3F37E4C(v8); sub_3F37D60(v8, v26); sub_3F37A10(v8, 1); */
            PC_TRACE(0x03F41BA8u, "FSDMGR_ALLOC",
                "sub_3F41BA8 entered R0=0x%08X R1=0x%08X LR=0x%08X SP=0x%08X\n");
            PC_TRACE(0x03F35EB4u, "FSDMGR_WRAP",
                "sub_3F35EB4 entered R0=0x%08X R1=0x%08X LR=0x%08X SP=0x%08X\n");
            PC_TRACE(0x03F37D60u, "FSDMGR_DRVPATH",
                "sub_3F37D60 entered R0=0x%08X R1=0x%08X LR=0x%08X SP=0x%08X\n");
            PC_TRACE(0x03F37A10u, "FSDMGR_DRV_RUN",
                "sub_3F37A10 entered R0=0x%08X R1=0x%08X LR=0x%08X SP=0x%08X\n");

            /* Reg wrappers. */
            tm.OnPc(0x03F3A7F8u, [](const TraceContext& c) {
                LOG(Trace, "[FSDMGR_REGQ] hkey=R0=0x%08X name_ptr=R1=0x%08X "
                           "buf=R2=0x%08X buflen=R3=0x%08X LR=0x%08X SP=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                    c.regs[14], c.regs[13]);
            });
            tm.OnPc(0x03F3A8D4u, [](const TraceContext& c) {
                LOG(Trace, "[FSDMGR_OPENSUB] hkey=R0=0x%08X name=R1=0x%08X "
                           "out=R2=0x%08X LR=0x%08X SP=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2],
                    c.regs[14], c.regs[13]);
            });
            tm.OnPc(0x03F3A8FCu, [](const TraceContext& c) {
                LOG(Trace, "[FSDMGR_OPENKEY] path_ptr=R0=0x%08X out=R1=0x%08X "
                           "LR=0x%08X SP=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14], c.regs[13]);
            });
            tm.OnPc(0x03F34DCCu, [](const TraceContext& c) {
                LOG(Trace, "[FSDMGR_ENUMER] hkey=R0=0x%08X filter_a2=R1=0x%08X "
                           "LR=0x%08X SP=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14], c.regs[13]);
            });
            tm.OnPc(0x03F3A8A8u, [](const TraceContext& c) {
                LOG(Trace, "[FSDMGR_ENUMKEY] hkey=R0=0x%08X idx=R1=0x%08X "
                           "name_buf=R2=0x%08X name_len=R3=0x%08X LR=0x%08X SP=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                    c.regs[14], c.regs[13]);
            });

            /* Precise call-site hooks inside sub_3F3840C — the bare
               function-entry hooks above fire on first translation
               from any caller, but the call-site hooks below confirm
               what sub_3F3840C actually passes/receives in its calls. */
            PC_TRACE(0x03F38440u, "FSDMGR_OPEN_RET",
                "post-BL sub_3F3A8FC return R0(0=success)=0x%08X R1=0x%08X LR=0x%08X SP=0x%08X\n");
            PC_TRACE(0x03F38460u, "FSDMGR_ENUMER_BL",
                "BL sub_3F34DCC hkey=R0=0x%08X filter_a2=R1=0x%08X LR=0x%08X SP=0x%08X\n");
            PC_TRACE(0x03F38464u, "FSDMGR_ENUMER_RET",
                "post-BL sub_3F34DCC return R0(0=empty)=0x%08X R1=0x%08X LR=0x%08X SP=0x%08X\n");

            /* fsdmgr .data init audit at sub_3F3840C+0x30 (BL sub_3F3A8FC).
               realaddr+0x1F0 (kernel runtime) and dataptr+0x1F0 (PE init
               source) should both hold 0x03F31FD0 ("System\StorageManager
               \AutoLoad" string ptr). */
            tm.OnPc(0x03F3843Cu, [](const TraceContext& c) {
                auto& mem = c.emu.Get<EmulatedMemory>();
                auto& pt  = c.emu.Get<PageTableBuilder>();
                auto try_read_via_mmu = [&](uint32_t va) -> uint32_t {
                    return c.ReadVa32(va).value_or(0xDEADBEEFu);
                };
                auto try_read_kernel = [&](uint32_t va) -> uint32_t {
                    const uint32_t pa = pt.VaToPa(va);
                    if (pa == 0u) return 0xDEADBEEFu;
                    return mem.ReadWord(pa);
                };
                const uint32_t realaddr_0   = try_read_via_mmu(0x01FFB000u);
                const uint32_t realaddr_1F0 = try_read_via_mmu(0x01FFB1F0u);
                const uint32_t dataptr_0    = try_read_kernel(0x800BBDC8u);
                const uint32_t dataptr_1F0  = try_read_kernel(0x800BBFB8u);
                char scan[4096]; int slen = 0;
                slen += std::snprintf(scan + slen, sizeof(scan) - slen,
                    "[FSDMGR_DATA_SCAN] dataptr 0x800BBDC8 .data scan (0..0x3F8):\n");
                for (uint32_t off = 0; off < 0x400u && slen < (int)sizeof(scan) - 32; off += 4) {
                    const uint32_t v = try_read_kernel(0x800BBDC8u + off);
                    if ((off & 0x3Cu) == 0) {
                        slen += std::snprintf(scan + slen, sizeof(scan) - slen,
                            "\n  +0x%03X:", off);
                    }
                    slen += std::snprintf(scan + slen, sizeof(scan) - slen,
                        " %08X", v);
                }
                LOG(Trace, "[FSDMGR_DATA_CHECK] fsdmgr .data init audit:\n"
                           "  realaddr+0x000=0x01FFB000 -> 0x%08X\n"
                           "  realaddr+0x1F0=0x01FFB1F0 -> 0x%08X (AutoLoad ptr slot)\n"
                           "  dataptr +0x000=0x800BBDC8 -> 0x%08X\n"
                           "  dataptr +0x1F0=0x800BBFB8 -> 0x%08X\n"
                           "  EXPECTED AutoLoad ptr slot: 0x03F31FD0\n"
                           "%s\n",
                    realaddr_0, realaddr_1F0, dataptr_0, dataptr_1F0, scan);
            });

            /* coredll sub_3FC1310 — raises exception code 0xC0000094.
               Reference TX fires 2x. */
            PC_TRACE(0x03FC1310u, "CDLL_RAISE_A",
                "coredll sub_3FC1310 entered R0=0x%08X R1=0x%08X LR=0x%08X SP=0x%08X\n");
            /* coredll CaptureDumpFileOnDevice — second RaiseException
               site (PSL 0xF000FE38 code 278). */
            PC_TRACE(0x03F7DAF8u, "CDLL_RAISE_B",
                "coredll CaptureDumpFileOnDevice entered R0=0x%08X R1=0x%08X LR=0x%08X SP=0x%08X\n");
        });
    }
};

#undef PC_TRACE

REGISTER_SERVICE(TraceWm5FsdmgrChain);

}  /* namespace */

