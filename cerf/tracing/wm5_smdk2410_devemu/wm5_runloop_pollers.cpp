#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../peripherals/cerf_virt/cerf_virt_framebuffer.h"
#include "../../peripherals/cerf_virt/cerf_virt_addr_map.h"
#include "../../host/host_screenshot.h"
#include "wm5_bundle.h"

#include <atomic>
#include <cstdint>

namespace {

/* RunLoop pollers — fire on every JIT Run() return. Each tracks a
   value-of-interest and logs only on CHANGE (single line per
   transition, not per iter). Service members hold the state so we
   stay clear of static-locals-in-lambda. */

class TraceWm5RunLoopPollers : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kWm5BundleCrc32, [&] {
            /* UserSampler/AnyPcSampler: unbounded per-PC dumps, disabled (certmod-loop only). */
            /* tm.OnRunLoopIter([this](const TraceContext& c) { UserSampler  (c); }); */
            /* tm.OnRunLoopIter([this](const TraceContext& c) { AnyPcSampler (c); }); */
            tm.OnRunLoopIter([this](const TraceContext& c) { CertModData  (c); });
            tm.OnRunLoopIter([this](const TraceContext& c) { L1Fs         (c); });
            tm.OnRunLoopIter([this](const TraceContext& c) { L2Page0xDC   (c); });
            tm.OnRunLoopIter([this](const TraceContext& c) { SavedLrPoll  (c); });
            tm.OnRunLoopIter([this](const TraceContext& c) { FlagsPoll    (c); });
            tm.OnRunLoopIter([this](const TraceContext& c) { DiagPeriodic (c); });
            tm.OnRunLoopIter([this](const TraceContext& c) { TemplatePoll (c); });
            tm.OnRunLoopIter([this](const TraceContext& c) { ShotCadence  (c); });
        });
    }

private:
    /* Every Run() return at PC in slot 0 (< 0x02000000) names the
       user process's resume PC. */
    void UserSampler(const TraceContext& c) {
        if (c.pc >= 0x02000000u) return;
        if (c.pc == user_pc_last_.load(std::memory_order_relaxed)) return;
        user_pc_last_.store(c.pc, std::memory_order_relaxed);
        const uint64_t n = ++user_pc_count_;
        LOG(Trace, "[USER] n=%llu pc=0x%08X r0=0x%08X r1=0x%08X "
                   "r2=0x%08X r3=0x%08X lr=0x%08X sp=0x%08X\n",
            (unsigned long long)n, c.pc,
            c.regs[0], c.regs[1], c.regs[2], c.regs[3],
            c.regs[14], c.regs[13]);
    }

    /* Fires on every PC change. Inside CertMod's DllEntryPoint range,
       also peeks the saved-LR stack slot at [SP+20]. */
    void AnyPcSampler(const TraceContext& c) {
        if (c.pc == any_pc_last_.load(std::memory_order_relaxed)) return;
        any_pc_last_.store(c.pc, std::memory_order_relaxed);
        const uint64_t n = ++any_pc_count_;
        if (n > 500 && (n & 0xFFu) != 0) return;
        auto saved_lr = std::optional<uint32_t>{};
        if (c.pc >= 0x03F58000u && c.pc < 0x03F58500u) {
            saved_lr = c.ReadVa32(c.regs[13] + 20u);
        }
        LOG(Trace, "[ANYPC] n=%llu pc=0x%08X r0=0x%08X r1=0x%08X "
                   "r2=0x%08X r3=0x%08X lr=0x%08X sp=0x%08X "
                   "saved_lr=%s\n",
            (unsigned long long)n, c.pc,
            c.regs[0], c.regs[1], c.regs[2], c.regs[3],
            c.regs[14], c.regs[13],
            saved_lr
                ? (*saved_lr == 0x03F5842Cu
                      ? "0x03F5842C [SELF!]"
                      : "other")
                : "unmapped");
        if (saved_lr && *saved_lr != 0x03F5842Cu) {
            LOG(Trace, "[ANYPC]    saved_lr value: 0x%08X\n", *saved_lr);
        }
    }

    /* MEMORY[0x05FFD484] — read by CertMod's DllEntryPoint at
       fdwReason=1 (LDR R3,[R5]; BX R3). 0x03F5842C means BX
       recursively re-enters DllEntryPoint = loop trigger. */
    void CertModData(const TraceContext& c) {
        const auto v = c.ReadVa32(0x05FFD484u);
        if (!v) return;
        const uint32_t prev = certmod_last_.exchange(*v, std::memory_order_relaxed);
        if (prev == *v) return;
        LOG(Trace, "[CERTMOD_DATA] MEMORY[0x05FFD484]: 0x%08X -> 0x%08X %s\n",
            prev, *v,
            *v == 0x03F5842Cu ? "(= DllEntryPoint!) LOOP TRIGGER"
            : *v == 0           ? "(zero — DllEntryPoint skips BX R3)"
                                : "(some function pointer)");
    }

    /* L1[0x40] @ PA 0x314A0100 for filesys slot 2. FSR=5 section
       translation fault means entry invalid. */
    void L1Fs(const TraceContext& c) {
        auto& mem = c.emu.Get<EmulatedMemory>();
        const uint32_t v = mem.ReadWord(0x314A0100u);
        const uint32_t prev = l1_fs_last_.exchange(v, std::memory_order_relaxed);
        if (prev == v) return;
        LOG(Trace, "[L1_FS] L1[0x40] (PA 0x314A0100) for filesys slot 2: "
                   "0x%08X -> 0x%08X\n", prev, v);
    }

    /* L2[0xDC] @ PA 0x3FF5A370 — L2 entry for page 0xDC in slot 2's
       L2 table (which L1[0x40]=0x3FF5A001 points to). The lazy-page-
       fill abort fires when this entry is 0 but L1[0x40] is set.
       Knowing when/who clears this entry pins the root cause. */
    void L2Page0xDC(const TraceContext& c) {
        auto& mem = c.emu.Get<EmulatedMemory>();
        const uint32_t v = mem.ReadWord(0x3FF5A370u);
        const uint32_t prev = l2_dc_last_.exchange(v, std::memory_order_relaxed);
        if (prev == v) return;
        LOG(Trace, "[L2_DC] L2[0xDC] (PA 0x3FF5A370) slot2 page 0xDC: "
                   "0x%08X -> 0x%08X\n", prev, v);
    }

    /* DllEntryPoint's saved-LR slot at 0x0406F9BC. */
    void SavedLrPoll(const TraceContext& c) {
        const auto v = c.ReadVa32(0x0406F9BCu);
        if (!v) return;
        const uint64_t iter = ++saved_lr_count_;
        const uint32_t prev = saved_lr_last_.exchange(*v, std::memory_order_relaxed);
        if (prev == *v) return;
        LOG(Trace, "[SAVED_LR_POLL] 0x0406F9BC: 0x%08X -> 0x%08X at iter=%llu\n",
            prev, *v, (unsigned long long)iter);
    }

    /* dword_48058 (filesys's Flags / Start DevMgr flag byte). */
    void FlagsPoll(const TraceContext& c) {
        const auto v = c.ReadVa32(0x48058u);
        if (!v) return;
        const uint32_t prev = flags_last_.exchange(*v, std::memory_order_relaxed);
        if (prev == *v) return;
        LOG(Trace, "[FLAGS_POLL] dword_48058 changed: 0x%08X -> 0x%08X "
                   "at PC=0x%08X SP=0x%08X LR=0x%08X\n",
            prev, *v, c.pc, c.regs[13], c.regs[14]);
    }

    /* Periodic snapshot: coredll literal at IDA 0x8008A8F0
       (PA 0x3008A8F0) — expected 0x80071FB4 ("coredll.dll" string).
       LSB set = system loader path. */
    void DiagPeriodic(const TraceContext& c) {
        const uint64_t n = ++diag_count_;
        if (n > 8 && (n & 0xFFu) != 0) return;
        auto& mem = c.emu.Get<EmulatedMemory>();
        const uint32_t last_err  = mem.ReadWord(0x3FFFF05Cu);
        const uint32_t lit_str   = mem.ReadWord(0x3008A8F0u);
        const uint32_t coredll_h = mem.ReadWord(0x314C6060u);
        LOG(Trace, "[DIAG] err=%u lit_string=0x%08X (LSB=%u) "
                   "coredll_h=0x%08X PC=0x%08X iter=%llu\n",
            last_err, lit_str, lit_str & 1u, coredll_h,
            c.pc, (unsigned long long)n);
    }

    /* Poll the shared bar template (FB-PA 0xD01B7490, stride 960) on a 5x4 grid:
       logs each grid-point content change + PC, to see whether the surface is
       (re)drawn between its realloc and the copy that reads it (stale vs fresh). */
    void TemplatePoll(const TraceContext& c) {
        auto* fb = c.emu.TryGet<CerfVirtFramebuffer>();
        if (!fb) return;
        static const int32_t kRows[5] = { 0, 8, 13, 20, 25 };
        static const int32_t kCols[4] = { 0, 80, 160, 239 };
        const uint32_t base = 0xD01B7490u - CerfVirt::kFramebufferMemBase;
        for (int r = 0; r < 5; ++r) {
            for (int col = 0; col < 4; ++col) {
                const int idx = r * 4 + col;
                const uint32_t off = base + (uint32_t)kRows[r] * 960u
                                          + (uint32_t)kCols[col] * 4u;
                if (off + 4u > fb->RegionBytes()) continue;
                const uint32_t v = *reinterpret_cast<const uint32_t*>(fb->Bytes() + off);
                const uint32_t prev = templ_grid_last_[idx].exchange(v, std::memory_order_relaxed);
                if (prev == v) continue;
                LOG(Trace, "[TEMPL] px(%d,%d) 0x%08X -> 0x%08X PC=0x%08X LR=0x%08X SP=0x%08X\n",
                    kCols[col], kRows[r], prev, v, c.pc, c.regs[14], c.regs[13]);
            }
        }
    }

    /* Periodically save a host screenshot so the magenta-sentinel result
       (composite-of-uninitialized bar surface) is captured without UI
       interaction. Cadence by runloop iter; capped. */
    void ShotCadence(const TraceContext& c) {
        const uint64_t n = ++shot_iter_;
        if ((n % 250000ull) != 0ull) return;
        if (shot_count_.fetch_add(1, std::memory_order_relaxed) >= 16u) return;
        c.emu.Get<HostScreenshot>().Save();
    }

    std::atomic<uint64_t> shot_iter_  {0};
    std::atomic<uint32_t> shot_count_ {0};
    std::atomic<uint32_t> templ_grid_last_[20]{
        {0xCAFEBABEu},{0xCAFEBABEu},{0xCAFEBABEu},{0xCAFEBABEu},
        {0xCAFEBABEu},{0xCAFEBABEu},{0xCAFEBABEu},{0xCAFEBABEu},
        {0xCAFEBABEu},{0xCAFEBABEu},{0xCAFEBABEu},{0xCAFEBABEu},
        {0xCAFEBABEu},{0xCAFEBABEu},{0xCAFEBABEu},{0xCAFEBABEu},
        {0xCAFEBABEu},{0xCAFEBABEu},{0xCAFEBABEu},{0xCAFEBABEu} };
    std::atomic<uint32_t> user_pc_last_  {0xFFFFFFFFu};
    std::atomic<uint64_t> user_pc_count_ {0};
    std::atomic<uint32_t> any_pc_last_   {0};
    std::atomic<uint64_t> any_pc_count_  {0};
    std::atomic<uint32_t> certmod_last_  {0xCAFEBABEu};
    std::atomic<uint32_t> l1_fs_last_    {0xCAFEBABEu};
    std::atomic<uint32_t> l2_dc_last_    {0xCAFEBABEu};
    std::atomic<uint32_t> saved_lr_last_ {0};
    std::atomic<uint64_t> saved_lr_count_{0};
    std::atomic<uint32_t> flags_last_    {0xDEADBEEFu};
    std::atomic<uint64_t> diag_count_    {0};
};

REGISTER_SERVICE(TraceWm5RunLoopPollers);

}  /* namespace */
