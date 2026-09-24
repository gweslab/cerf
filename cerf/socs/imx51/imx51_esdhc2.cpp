#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <array>
#include <cstdint>

namespace {

/* i.MX51 eSDHC2 (Enhanced SD Host Controller, MCIMX51RM Ch 31) at SPBA0 0x70008000.
   Modelled with no card present (SD slot is non-boot-critical) - there is no card
   transaction model behind it, so the present-state must report CINS=0. */
constexpr uint32_t kBase = 0x70008000u;
constexpr uint32_t kSize = 0x00004000u;  /* SPBA0 16 KB slot */

/* Register offsets (MCIMX51RM Table 31-2). */
constexpr uint32_t kOffXfertyp   = 0x0Cu;  /* Transfer Type (command issue) */
constexpr uint32_t kOffPrsstat   = 0x24u;  /* Present State (RO) */
constexpr uint32_t kOffSysctl    = 0x2Cu;  /* System Control */
constexpr uint32_t kOffIrqstat   = 0x30u;  /* Interrupt Status (W1C) */
constexpr uint32_t kOffHostcap   = 0x40u;  /* Host Controller Capabilities (RO) */
constexpr uint32_t kOffHostver   = 0xFCu;  /* Host Controller Version (RO) */

/* SYSCTL reset = SDCLKFS=0x80 (bits 15:8) + SDCLKEN (bit3) (Figure 31-12). */
constexpr uint32_t kSysctlReset = 0x00008008u;
/* SYSCTL software-reset / init-active bits self-clear once the action completes
   (RSTA b24 / RSTC b25 / RSTD b26 / INITA b27, §31.3.3.9); CERF completes them
   instantly, so they always read back 0. */
constexpr uint32_t kSysctlSelfClear = (1u << 24) | (1u << 25) | (1u << 26) | (1u << 27);

/* HOSTCAPBLT (RO, Figure 31-17): VS18|VS30|VS33|SRS|DMAS|HSS|ADMAS=1, MBL=011. */
constexpr uint32_t kHostcap = 0x07F30000u;
/* HOSTVER (RO, Figure 31-23): VVN=0x12 (eSDHC v2.x), SVN=0x01. */
constexpr uint32_t kHostver = 0x00001201u;
/* PRSSTAT (RO, Figure 31-10): DAT/CMD lines idle-high (DLSL=0xFF, CLSL=1), SD clock
   stable (SDSTB b3=1), no card (CINS b16=0), not busy (CIHB/CDIHB/DLA=0). */
constexpr uint32_t kPrsstat = 0xFF800008u;

/* XFERTYP RSPTYP (Figure 31-7, bits 17:16): nonzero = a response is expected.
   esdhc.dll's command builder (sub_C0AF1E5C) leaves these 0 only for the
   no-response commands (e.g. CMD0); every response-expecting command sets a
   RSPTYP bit. */
constexpr uint32_t kXfertypRsptypMask = 0x3u << 16;
/* IRQSTAT command-completion bits (Figure 31-13 / Table 31-17). */
constexpr uint32_t kIrqstatCc   = 1u << 0;   /* Command Complete */
constexpr uint32_t kIrqstatCtoe = 1u << 16;  /* Command Timeout Error */

class Imx51Esdhc2 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override {
        regs_[kOffSysctl >> 2] = kSysctlReset;
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint8_t ReadByte(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        return static_cast<uint8_t>(ReadReg(off & ~3u) >> ((off & 3u) * 8u));
    }
    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        return static_cast<uint16_t>(ReadReg(off & ~3u) >> ((off & 2u) * 8u));
    }
    uint32_t ReadWord(uint32_t addr) override { return ReadReg(addr - kBase); }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;
        switch (off) {
            case kOffXfertyp:
                /* esdhc.dll's polled completion handler (sub_C0AF2E88) advances
                   ONLY when IRQSTAT.CC is set, so omitting CC spins its busy-poll
                   forever and the boot hangs; CTOE is the no-card response timeout
                   for a response-expecting command (Table 31-18). */
                regs_[off >> 2] = value;
                regs_[kOffIrqstat >> 2] |= kIrqstatCc
                    | ((value & kXfertypRsptypMask) ? kIrqstatCtoe : 0u);
                return;
            case kOffSysctl:
                regs_[off >> 2] = value & ~kSysctlSelfClear;
                return;
            case kOffIrqstat:
                regs_[off >> 2] &= ~value;  /* write-1-clear */
                return;
            case kOffPrsstat:   /* RO */
            case kOffHostcap:   /* RO (writes ignored, §31.3.3.14) */
            case kOffHostver:   /* RO */
                return;
            default:
                regs_[off >> 2] = value;
                return;
        }
    }

    void SaveState(StateWriter& w) override { w.WriteBytes("regs", regs_.data(), sizeof(regs_)); }
    void RestoreState(StateReader& r) override { r.ReadBytes("regs", regs_.data(), sizeof(regs_)); }

private:
    uint32_t ReadReg(uint32_t off) const {
        switch (off) {
            case kOffPrsstat: return kPrsstat;
            case kOffHostcap: return kHostcap;
            case kOffHostver: return kHostver;
            default:          return regs_[off >> 2];
        }
    }

    std::array<uint32_t, kSize / 4> regs_{};
};

}  /* namespace */

REGISTER_SERVICE(Imx51Esdhc2);
