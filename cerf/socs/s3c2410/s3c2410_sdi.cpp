#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

/* S3C2410 SD/MMC host (SDI) at PA 0x5A000000 (S3C2410A manual §19), present-no-card.
   Card detection is a GPIO line, not an SDI register (sdhc_smdk2410.dll sub_340282C
   samples CardDetectGPIO), so the SDI block never signals a card → the SD stack
   issues no command and polls no SDI status register; a passive reset file suffices. */

namespace {

constexpr uint32_t kBase = 0x5A000000u;
constexpr uint32_t kSize = 0x00000044u;        /* SDICON(0x00)..SDIIMSK(0x40) */
constexpr uint32_t kRegCount = kSize / 4u;     /* 17 registers */

/* Register offsets (S3C2410A §19, addresses read from each register's own
   address row in the manual). */
constexpr uint32_t kSdiCon     = 0x00u;        /* RW  reset 0x0    */
constexpr uint32_t kSdiPre     = 0x04u;        /* RW  reset 0x0    */
constexpr uint32_t kSdiCmdArg  = 0x08u;        /* RW  reset 0x0    */
constexpr uint32_t kSdiCmdCon  = 0x0Cu;        /* RW  reset 0x0    */
constexpr uint32_t kSdiCmdSta  = 0x10u;        /* R/(W) W1C reset 0x0 */
constexpr uint32_t kSdiRsp0    = 0x14u;        /* R   reset 0x0    */
constexpr uint32_t kSdiRsp1    = 0x18u;        /* R   reset 0x0    */
constexpr uint32_t kSdiRsp2    = 0x1Cu;        /* R   reset 0x0    */
constexpr uint32_t kSdiRsp3    = 0x20u;        /* R   reset 0x0    */
constexpr uint32_t kSdiDTimer  = 0x24u;        /* RW  reset 0x2000 */
constexpr uint32_t kSdiBSize   = 0x28u;        /* RW  reset 0x0    */
constexpr uint32_t kSdiDCon    = 0x2Cu;        /* RW  reset 0x0    */
constexpr uint32_t kSdiDCnt    = 0x30u;        /* R   reset 0x0    */
constexpr uint32_t kSdiDSta    = 0x34u;        /* R/(W) W1C reset 0x0 */
constexpr uint32_t kSdiFSta    = 0x38u;        /* R   reset 0x0    */
constexpr uint32_t kSdiDat     = 0x3Cu;        /* RW  reset 0x0    */
constexpr uint32_t kSdiIMsk    = 0x40u;        /* RW  reset 0x0    */

constexpr uint32_t kSdiDTimerReset = 0x2000u;  /* §19 SDIDTIMER reset value */

class S3C2410Sdi : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::S3c2410;
    }

    void OnReady() override {
        ResetRegs();
        emu_.Get<PeripheralDispatcher>().Register(this);
        LOG(Boot, "S3C2410Sdi: SD/MMC host at PA 0x%08X (present-no-card)\n", kBase);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        if (off & 3u) HaltUnsupportedAccess("ReadWord(unaligned)", addr, 0);
        /* Idle silicon: every status register reads its reset (0). The stored
           file already holds those values, so no per-register special-casing. */
        return regs_[off / 4u];
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;
        if (off & 3u) HaltUnsupportedAccess("WriteWord(unaligned)", addr, value);
        switch (off) {
        /* Read-only registers (§19): writes are dropped. */
        case kSdiRsp0: case kSdiRsp1: case kSdiRsp2: case kSdiRsp3:
        case kSdiDCnt: case kSdiFSta:
            return;
        /* R/(W) status: a flag bit is cleared by writing 1 to it (§19). At idle
           every bit is already 0, so this is a no-op, but it is the faithful
           write semantics. */
        case kSdiCmdSta: case kSdiDSta:
            regs_[off / 4u] &= ~value;
            return;
        default:
            regs_[off / 4u] = value;
            return;
        }
    }

    void SaveState(StateWriter& w) override {
        for (uint32_t i = 0; i < kRegCount; ++i) w.Write("regs", regs_[i]);
    }
    void RestoreState(StateReader& r) override {
        for (uint32_t i = 0; i < kRegCount; ++i) r.Read("regs", regs_[i]);
    }

private:
    void ResetRegs() {
        for (uint32_t i = 0; i < kRegCount; ++i) regs_[i] = 0u;
        regs_[kSdiDTimer / 4u] = kSdiDTimerReset;
    }

    uint32_t regs_[kRegCount] = {};
};

}  /* namespace */

REGISTER_SERVICE(S3C2410Sdi);
