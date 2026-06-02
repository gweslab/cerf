#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "devemu_wm65_bundle.h"

namespace {

struct Probe {
    uint32_t    pa;
    const char* what;
    uint32_t    expected;
};

constexpr Probe kProbes[] = {
    /* FTL mapping entry I wrote for mod_hdr — flags word. */
    { 0x05FFF074u, "ftl_mod_hdr_flags",   0xFFFBFFFFu },
    /* FTL mapping entry I wrote — ls word (sector value). */
    { 0x05FFF070u, "ftl_mod_hdr_ls",      0x00003357u },
    /* mod_hdr data page +0x08 — e32_vbase I planted (orig_vbase). */
    { 0x05FFE008u, "modhdr_e32_vbase",    0x7B584000u },
    /* Original dirent file_size field — I overwrote to 208 (=0xD0). */
    { 0x021130BCu, "orig_dirent_size",    0x000000D0u },
    /* Patched mod_indexptr destination (PA=tr.Translate(0x01C16EC0)=0x20F5EC0).
       First 4 bytes = packed (comp_sz=4096, full_sz=4096) = 0x10001000. */
    { 0x020F5EC0u, "patched_idx_szs",     0x10001000u },
    /* Same record +4 = ptr to my mod_hdr LA = 0x030A7000. */
    { 0x020F5EC4u, "patched_idx_ptr",     0x030A7000u },
    /* Section 0 data page start (phys_page=23805 = PA 0x05FFD000).
       Whatever bytes injector wrote — expected just != 0xFFFFFFFF/0. */
    { 0x05FFD000u, "sec0_first4",         0u },
    /* Section 0 + 0x100 — somewhere in the middle. */
    { 0x05FFD100u, "sec0_at_0x100",       0u },
    /* Section 0 + 0x400 — well past PE prologue area. */
    { 0x05FFD400u, "sec0_at_0x400",       0u },
};

class TraceWm65ImgfsFtlPersist : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kDevemuWm65BundleCrc32, [this, &tm] {
            /* cerf_guest entry VA = orig_vbase (0x7B584000) + entry_rva (0x1D10).
               Filter by byte-signature (STR LR,[SP,-4]! = 0xE52DE004). */
            tm.OnPcFiltered(
                0x7B585D10u,
                [](const TraceContext& c) {
                    auto v = c.ReadVa32(0x7B585D10u);
                    return v.has_value() && *v == 0xE52DE004u;
                },
                [](const TraceContext& c) {
                    LOG(Trace, "[WM65_FTL] *** cerf_guest DllEntry FIRED *** "
                               "R0=0x%08X R1=0x%08X LR=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[14]);
                });

            /* WM6.5 kernel IMGFS-block magic validator entry — fires per
               4KB dirent block validation. If never fires, kernel never
               walks dirent blocks at all in the window. */
            tm.OnPc(0x88240858u, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n <= 5 || (n % 100) == 0) {
                    LOG(Trace, "[KBOOT] magic_validator @0x88240858 fire#%u "
                               "R0=0x%08X R1=0x%08X LR=0x%08X\n",
                        n, c.regs[0], c.regs[1], c.regs[14]);
                }
            });

            /* WM6.5 kernel dirent search-by-kind entry — fires per
               kernel module/section/name lookup. */
            tm.OnPc(0x88240D2Cu, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n <= 10 || (n % 50) == 0) {
                    LOG(Trace, "[KBOOT] search_by_kind @0x88240D2C fire#%u "
                               "R0=0x%08X R1=0x%08X R2=0x%08X (kind) LR=0x%08X\n",
                        n, c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
                }
            });

            /* WM6.5 kernel big module-load function entry — fires per
               module load attempt. R0=context, R1=name-related arg. */
            tm.OnPc(0x88240E7Cu, [](const TraceContext& c) {
                static uint32_t n = 0;
                ++n;
                LOG(Trace, "[KBOOT] big_module_load @0x88240E7C fire#%u "
                           "R0=0x%08X R1=0x%08X R2=0x%08X LR=0x%08X\n",
                    n, c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });

            /* Mechanism verification: PERF shows this kernel UART MMIO PC
               hit 627x in 4s of boot. If this fires, OnPc works on kernel
               VAs and the silence on IMGFS hooks means those functions
               aren't reached. */
            tm.OnPc(0x88071E20u, [](const TraceContext&) {
                static uint32_t n = 0;
                ++n;
                if (n <= 3 || (n % 200) == 0) {
                    LOG(Trace, "[OnPcOK] kernel @0x88071E20 fire#%u\n", n);
                }
            });
            tm.OnPc(0xA8240858u, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n <= 5 || (n % 100) == 0) {
                    LOG(Trace, "[KBOOT-U] magic_validator @0xA8240858 fire#%u "
                               "R0=0x%08X LR=0x%08X\n",
                        n, c.regs[0], c.regs[14]);
                }
            });
            tm.OnPc(0xA8240D2Cu, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n <= 10 || (n % 50) == 0) {
                    LOG(Trace, "[KBOOT-U] search_by_kind @0xA8240D2C fire#%u "
                               "R0=0x%08X R1=0x%08X R2=0x%08X (kind) LR=0x%08X\n",
                        n, c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
                }
            });
            tm.OnPc(0xA8240E7Cu, [](const TraceContext& c) {
                static uint32_t n = 0;
                ++n;
                LOG(Trace, "[KBOOT-U] big_module_load @0xA8240E7C fire#%u "
                           "R0=0x%08X R1=0x%08X R2=0x%08X LR=0x%08X\n",
                    n, c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnRunLoopIter([this](const TraceContext& c) {
                /* Track whether VA 0x7B585A34 (cerf_guest entry slot) ever
                   becomes TLB-resident. nullopt = page not mapped at this poll. */
                if (!entry_va_seen_) {
                    auto v = c.ReadVa32(0x7B585D10u);
                    if (v.has_value()) {
                        entry_va_seen_ = true;
                        const char* tag = (*v == 0xE52DE004u)
                            ? "MATCHES cerf_guest prologue (STR LR,[SP,-4]!)"
                            : "DIFFERENT BYTES — original DLL is loaded here";
                        LOG(Trace, "[WM65_FTL] entry VA 0x7B585D10 became "
                                   "TLB-resident: value=0x%08X (%s)\n",
                            *v, tag);
                    }
                }
                auto& mem = c.emu.Get<EmulatedMemory>();
                for (size_t i = 0; i < std::size(kProbes); ++i) {
                    const uint32_t v = mem.ReadWord(kProbes[i].pa);
                    if (!seen_first_[i]) {
                        seen_first_[i] = true;
                        last_[i]       = v;
                        LOG(Trace, "[WM65_FTL] first poll %s pa=0x%08X "
                                   "val=0x%08X (expected=0x%08X) %s\n",
                            kProbes[i].what, kProbes[i].pa, v,
                            kProbes[i].expected,
                            v == kProbes[i].expected ? "OK" : "MISMATCH");
                        continue;
                    }
                    if (v != last_[i]) {
                        LOG(Trace, "[WM65_FTL] CHANGED %s pa=0x%08X "
                                   "0x%08X -> 0x%08X\n",
                            kProbes[i].what, kProbes[i].pa, last_[i], v);
                        last_[i] = v;
                    }
                }
            });
        });
    }

private:
    bool     seen_first_[std::size(kProbes)] = {};
    uint32_t last_      [std::size(kProbes)] = {};
    bool     entry_va_seen_                  = false;
};

REGISTER_SERVICE(TraceWm65ImgfsFtlPersist);

}  /* namespace */
