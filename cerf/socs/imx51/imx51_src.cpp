#include "../../peripherals/peripheral_base.h"

#include "../guest_cpu_reset.h"

#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <atomic>
#include <cstdint>

namespace {

/* i.MX51 System Reset Controller (SRC), MCIMX51RM Ch 54, PA 0x73FD_0000 - reset
   status/control + ResetCauseLatch. Per-register resets cited below. */
constexpr uint32_t kBase = 0x73FD0000u;
constexpr uint32_t kSize = 0x00004000u;

constexpr uint32_t kScr  = 0x00u;
constexpr uint32_t kSbmr = 0x04u;
constexpr uint32_t kSrsr = 0x08u;
constexpr uint32_t kSisr = 0x14u;
constexpr uint32_t kSimr = 0x18u;

constexpr uint32_t kScrReset  = 0x0000051Fu;
constexpr uint32_t kSimrReset = 0x00000007u;

/* SRSR reset-source bits (Table 54-5). */
constexpr uint32_t kSrsrIppReset = 0x00000001u;  /* ipp_reset_b pin: power-on */
constexpr uint32_t kSrsrWdog     = 0x00000010u;  /* wdog_rst_b (bit 4)        */
constexpr uint32_t kSrsrWarmBoot = 0x00010000u;  /* warm_boot (bit 16)        */

class Imx51Src : public Peripheral, public ResetCauseLatch {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().SetCauseLatch(this);
    }

    /* SRSR reports the source of the most recent reset (Table 54-5); latched
       from the reset-delivery path on the JIT thread while guest reads/W1Cs. */
    void LatchColdReset() override     { srsr_.store(kSrsrIppReset, std::memory_order_release); }
    void LatchWarmReset() override     { srsr_.store(kSrsrWarmBoot, std::memory_order_release); }
    void LatchWatchdogReset() override { srsr_.store(kSrsrWdog,     std::memory_order_release); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        switch (addr - kBase) {
            case kScr:  return scr_;
            case kSbmr: return sbmr_;
            case kSrsr: return srsr_.load(std::memory_order_acquire);
            case kSisr: return sisr_;
            case kSimr: return simr_;
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        switch (addr - kBase) {
            case kScr:  scr_ = value; return;
            case kSbmr: return;  /* read-only boot-mode/fuse mirror */
            case kSrsr: srsr_.fetch_and(~value, std::memory_order_acq_rel); return;  /* W1C */
            case kSisr: sisr_ = value; return;
            case kSimr: simr_ = value; return;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    void SaveState(StateWriter& w) override {
        w.Write("scr", scr_);
        w.Write("srsr", srsr_.load(std::memory_order_acquire));
        w.Write("sisr", sisr_);
        w.Write("simr", simr_);
    }
    void RestoreState(StateReader& r) override {
        r.Read("scr", scr_);
        uint32_t s = 0; r.Read("srsr", s); srsr_.store(s, std::memory_order_release);
        r.Read("sisr", sisr_);
        r.Read("simr", simr_);
    }

private:
    uint32_t              scr_  = kScrReset;
    uint32_t              sbmr_ = 0;  /* boot-fuse mirror; no fuse dump, so modeled 0 */
    std::atomic<uint32_t> srsr_{kSrsrIppReset};
    uint32_t              sisr_ = 0;
    uint32_t              simr_ = kSimrReset;
};

}  /* namespace */

REGISTER_SERVICE(Imx51Src);
