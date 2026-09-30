#include "sa1111_unit.h"

#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../core/cerf_paths.h"
#include "../../core/string_utils.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../state/state_stream.h"
#include "sa1111_intc.h"
#include "sa1111_sbi.h"
#include "sa1111_serial_transfer.h"
#include "sa1111_system_controller.h"

#include <cstdint>
#include <fstream>
#include <vector>

namespace {

/* SA-1111 Developer's Manual §8.5 (printed 8-7): "dividing the standard input clock (3.6864
   MHz)"; §8.6.1.4 (printed 8-8): "the 3.6864 MHz clock produced by the on-chip PLL (143.7696
   divided by 39)". */
constexpr uint64_t kSspClockHz = 3686400u;

/* Table 8-3 (printed 8-9): DSS 3:0, FRF 5:4, bit 6 reserved, SSP_EN 7, SCR 15:8. Table 8-4
   (printed 8-12): LBM 2, SPO 3, SPH 4, TFT 10:7, RFT 14:11, "writes to reserved bits are
   ignored, and reads of these bits return zero". */
constexpr uint32_t kCr0Defined = 0xFFBFu;
constexpr uint32_t kCr0Sse     = 1u << 7;
constexpr uint32_t kCr1Defined = 0x7F9Cu;
constexpr uint32_t kCr1Lbm     = 1u << 2;
constexpr uint32_t kCr1Masks   = 0x3u;
constexpr uint32_t kDss8Bit    = 0x7u;

/* Table 8-6 (printed 8-15): TNF 2, RNE 3, BSY 4, TFS 5, RFS 6, RFL 15:12. */
constexpr uint32_t kSrTnf = 1u << 2;
constexpr uint32_t kSrRne = 1u << 3;
constexpr uint32_t kSrBsy = 1u << 4;
constexpr uint32_t kSrTfs = 1u << 5;
constexpr uint32_t kSrRfs = 1u << 6;

/* Table 11-1 (printed 11-3): 24 SspXmtint, 25 SspRcvint, 26 SspROR. */
constexpr uint8_t  kSrcXmt = 24u;
constexpr uint8_t  kSrcRcv = 25u;
constexpr uint64_t kSourceMask = (1ull << kSrcXmt) | (1ull << kSrcRcv) | (1ull << 26u);

class Sa1111Ssp : public Sa1111Unit {
public:
    using Sa1111Unit::Sa1111Unit;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Jornada720;
    }

    uint32_t MmioBase() const override { return 0x40000800u; }
    uint32_t MmioSize() const override { return 0x00000200u; }

    void SaveState(StateWriter& w) override {
        const uint64_t now = clock_->Cycles();
        Settle(now);
        w.Write<uint64_t>("eeprom_count", eeprom_.size());
        if (!eeprom_.empty()) w.WriteBytes("eeprom", eeprom_.data(), eeprom_.size());
        w.Write("cr0", cr0_);
        w.Write("cr1", cr1_);
        w.Write("phase", phase_);
        w.Write("addr", addr_);
        w.Write("rx", rx_);
        w.Write("status_reg", status_reg_);
        w.Write("rx_ready", rx_ready_);
        w.Write("wel", wel_);
        w.Write("tx", tx_);
        xfer_.Save(w, now);
    }
    void RestoreState(StateReader& r) override {
        uint64_t n = 0;
        r.Read("eeprom_count", n);
        eeprom_.resize(static_cast<size_t>(n));
        if (n) r.ReadBytes("eeprom", eeprom_.data(), static_cast<size_t>(n));
        r.Read("cr0", cr0_);
        r.Read("cr1", cr1_);
        r.Read("phase", phase_);
        r.Read("addr", addr_);
        r.Read("rx", rx_);
        r.Read("status_reg", status_reg_);
        r.Read("rx_ready", rx_ready_);
        r.Read("wel", wel_);
        r.Read("tx", tx_);
        xfer_.Restore(r, clock_->Cycles());
    }
    void PostRestore() override {
        const uint64_t now = clock_->Cycles();
        Settle(now);
        pub_ = Sample(now);
    }

protected:
    void OnUnitReady() override {
        const auto& cfg = emu_.Get<DeviceConfig>();
        if (!cfg.rom_eeprom.empty()) {
            const std::string path = ResolveDeviceFile(cfg.device_name,
                                                       cfg.rom_eeprom);
            std::ifstream f(Utf8ToWide(path.c_str()), std::ios::binary | std::ios::ate);
            if (f) {
                const std::streamsize n = f.tellg();
                f.seekg(0);
                eeprom_.resize(static_cast<size_t>(n));
                f.read(reinterpret_cast<char*>(eeprom_.data()), n);
                LOG(Boot, "Sa1111Ssp: loaded config EEPROM %s (%lld bytes)\n",
                    cfg.rom_eeprom.c_str(), static_cast<long long>(n));
            } else {
                LOG(Caution, "Sa1111Ssp: rom.eeprom '%s' not found at %s - "
                    "EEPROM reads float 0xFF (OAL uses default config)\n",
                    cfg.rom_eeprom.c_str(), path.c_str());
            }
        }
        clock_ = &emu_.Get<GuestCycleClock>();
        xfer_.Attach();
        emu_.Get<Sa1111SystemController>().RegisterClockListener([this] { OnClockChange(); });
        intc_ = &emu_.Get<Sa1111Intc>();
        intc_->RegisterSampler(kSourceMask, [this] { Publish(clock_->Cycles()); });
    }

    uint32_t UnitReadWord(uint32_t addr) override {
        const uint64_t now = clock_->Cycles();
        Publish(now);
        const uint32_t value = ReadReg(addr - MmioBase(), now);
        Publish(now);
        return value;
    }
    uint8_t UnitReadByte(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        return (uint8_t)(UnitReadWord(MmioBase() + (off & ~0x3u)) >> ((off & 0x3u) * 8u));
    }
    uint16_t UnitReadHalf(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        return (uint16_t)(UnitReadWord(MmioBase() + (off & ~0x3u)) >> ((off & 0x2u) * 8u));
    }

    void UnitWriteWord(uint32_t addr, uint32_t value) override {
        const uint64_t now = clock_->Cycles();
        Publish(now);
        WriteReg(addr - MmioBase(), value, now);
        Publish(now);
    }
    void UnitWriteByte(uint32_t addr, uint8_t value) override {
        const uint64_t now = clock_->Cycles();
        const uint32_t off = addr - MmioBase();
        Publish(now);
        if ((off & ~0x3u) == 0x40u) {
            WriteData(value, now);
        } else {
            const uint32_t shift = (off & 0x3u) * 8u;
            const uint32_t cur   = ReadReg(off & ~0x3u, now);
            WriteReg(off & ~0x3u, (cur & ~(0xFFu << shift)) | ((uint32_t)value << shift), now);
        }
        Publish(now);
    }

private:
    enum class Phase { Cmd, ReadAddr, ReadData, WriteAddr, WriteData,
                       RdsrData, WrsrData, Drain };

    struct Levels {
        bool xmt = false;
        bool rcv = false;
    };

    bool     Sse() const { return (cr0_ & kCr0Sse) != 0u; }
    uint32_t RxLevel() const { return rx_ready_ ? 1u : 0u; }

    /* §8.6.1.3 (printed 8-8): SSE "is the only control bit within the SSP which is reset to a
       known state"; "Clearing SSE also resets the SSP's FIFOs." */
    void OnChipReset(bool held) override {
        if (!held) return;
        const uint64_t now = clock_->Cycles();
        xfer_.Clear();
        cr0_ &= ~kCr0Sse;
        rx_ready_ = false;
        EndTransaction();
        Publish(now);
    }

    Levels Sample(uint64_t now) {
        Settle(now);
        Levels levels;
        levels.xmt = Sse();
        levels.rcv = Sse() && RxLevel() >= ((cr1_ >> 11) & 0xFu) + 1u;
        return levels;
    }

    void Publish(uint64_t now) {
        const Levels next = Sample(now);
        if (next.xmt != pub_.xmt) intc_->SetSourceLevel(kSrcXmt, next.xmt);
        if (next.rcv != pub_.rcv) intc_->SetSourceLevel(kSrcRcv, next.rcv);
        pub_ = next;
    }

    uint32_t Status(uint64_t now) {
        const Levels levels = Sample(now);
        uint32_t sr = kSrTnf | (RxLevel() << 12);
        if (rx_ready_)          sr |= kSrRne;
        if (xfer_.Busy(now))    sr |= kSrBsy;
        if (levels.xmt)         sr |= kSrTfs;
        if (levels.rcv)         sr |= kSrRfs;
        return sr;
    }

    uint32_t ReadReg(uint32_t off, uint64_t now) {
        switch (off) {
            case 0x00: return cr0_;
            case 0x04: return cr1_;
            case 0x10: return Status(now);
            case 0x40: return ReadData(now);
        }
        HaltUnsupportedAccess("ReadReg", MmioBase() + off, 0);
    }

    /* §8.6.4.8 (printed 8-14): "Writes to TNF, RNE, BSY, TFS, and RFS have no effect";
       §8.6.4.6: a one written to ROR clears it. */
    void WriteReg(uint32_t off, uint32_t value, uint64_t now) {
        switch (off) {
            case 0x00: WriteCr0(value, now); return;
            case 0x04: WriteCr1(value, now); return;
            case 0x10: return;
            case 0x40: WriteData(value, now); return;
        }
        HaltUnsupportedAccess("WriteReg", MmioBase() + off, value);
    }

    /* §8.6.1.3: "When the SSE bit is cleared during active operation, the SSP is disabled
       immediately, causing the current frame which is being transmitted to be terminated." */
    void WriteCr0(uint32_t value, uint64_t now) {
        value &= kCr0Defined;
        Settle(now);
        if (xfer_.Busy(now)) {
            if ((value & kCr0Sse) != 0u) {
                emu_.Get<Fatal>().Die("Sa1111Ssp: SSPCR0 write 0x%08X during a frame is not "
                                      "modelled", value);
            }
            xfer_.Clear();
        }
        cr0_ = value;
        if (!Sse()) rx_ready_ = false;
        EndTransaction();
    }

    /* §8.6.2.1 / §8.6.2.2 (printed 8-9 / 8-10) describe RIM and TIM, while Table 8-4 marks
       bits 1:0 reserved. */
    void WriteCr1(uint32_t value, uint64_t now) {
        Settle(now);
        if (xfer_.Busy(now) || (value & kCr1Masks) != 0u) {
            emu_.Get<Fatal>().Die("Sa1111Ssp: SSPCR1 write 0x%08X (during a frame, or with bits "
                                  "1:0 set) is not modelled", value);
        }
        cr1_ = value & kCr1Defined;
    }

    /* Table 8-3 (printed 8-9): "Bit rate = 3.6864x10^6 / 2x(SCR+1)"; Table 8-4 SPH: SCLK is
       inactive one full cycle at one end of the frame and one-half cycle at the other. */
    uint64_t FrameTicks() const {
        const uint64_t bits = (cr0_ & 0xFu) + 1u;
        return (2u * bits + 3u) * (((cr0_ >> 8) & 0xFFu) + 1u);
    }

    void RequireFormat() const {
        if ((cr0_ & 0x3Fu) == kDss8Bit && (cr1_ & kCr1Lbm) == 0u) return;
        emu_.Get<Fatal>().Die("Sa1111Ssp: SSP frame with SSPCR0 0x%08X / SSPCR1 0x%08X (not "
                              "8-bit Motorola SPI, or loop back) is not modelled", cr0_, cr1_);
    }

    void RequireClocks() const {
        const auto& sc  = emu_.Get<Sa1111SystemController>();
        const auto& sbi = emu_.Get<Sa1111Sbi>();
        if (sc.SspClockEnabled() && sc.PllRunningAtResetRate()) return;
        emu_.Get<Fatal>().Die("Sa1111Ssp: SSP frame with SKPCR SCLKEn clear, SKCR 0x%08X (PLL "
                              "not selected, Sleep or Doze), no 3.6864 MHz CLK input, or SKCDR "
                              "0x%08X (a PLL rate other than the reset one) is not modelled",
                              sbi.Skcr(), sc.Skcdr());
    }

    /* jornada720 jornada720.bin nk.exe sub_8004FF10 and hplib.dll sub_EA1C40: every SSPDR
       write waits for RNE, and SSPDR is read only for the frame clocked last. */
    void WriteData(uint32_t value, uint64_t now) {
        Settle(now);
        if (!Sse() || xfer_.Busy(now)) {
            emu_.Get<Fatal>().Die("Sa1111Ssp: SSPDR write 0x%08X with SSE clear or during a frame "
                                  "is not modelled", value);
        }
        RequireFormat();
        RequireClocks();
        rx_ready_ = false;
        tx_ = static_cast<uint8_t>(value);
        xfer_.Start(now, FrameTicks());
    }

    uint32_t ReadData(uint64_t now) {
        Settle(now);
        if (!rx_ready_) {
            emu_.Get<Fatal>().Die("Sa1111Ssp: SSPDR read with the receive FIFO empty is not "
                                  "modelled");
        }
        rx_ready_ = false;
        return rx_;
    }

    void Settle(uint64_t now) {
        if (!xfer_.Finished(now)) return;
        xfer_.Clear();
        ClockByte(tx_);
    }

    void OnClockChange() {
        const uint64_t now = clock_->Cycles();
        Settle(now);
        if (xfer_.Busy(now)) RequireClocks();
        Publish(now);
    }

    void EndTransaction() {
        if (phase_ == Phase::WriteData) wel_ = false;
        phase_ = Phase::Cmd;
    }

    uint8_t EepromByte(uint32_t a) const {
        return a < eeprom_.size() ? eeprom_[a] : 0xFFu;
    }

    /* jornada720 jornada720.bin hplib.dll sub_EA1C40: 1 WRSR, 2 WRITE, 3 READ, 4 WRDI, 5 RDSR,
       6 WREN. */
    void ClockByte(uint8_t tx) {
        switch (phase_) {
            case Phase::Cmd:
                rx_ = 0xFF;
                switch (tx) {
                    case 0x01: phase_ = Phase::WrsrData; break;
                    case 0x02: phase_ = Phase::WriteAddr; break;
                    case 0x03: phase_ = Phase::ReadAddr; break;
                    case 0x04: wel_ = false; break;
                    case 0x05: phase_ = Phase::RdsrData; break;
                    case 0x06: wel_ = true; break;
                    default:
                        emu_.Get<Fatal>().Die("Sa1111Ssp: EEPROM command 0x%02X is not "
                                              "modelled", tx);
                }
                break;
            case Phase::ReadAddr:
                addr_ = tx;
                phase_ = Phase::ReadData;
                rx_ = 0xFF;
                break;
            case Phase::ReadData:
                rx_ = EepromByte(addr_ & 0xFFu);
                addr_++;
                break;
            case Phase::WriteAddr:
                addr_ = tx;
                phase_ = Phase::WriteData;
                rx_ = 0xFF;
                break;
            case Phase::WriteData:
                if (wel_ && (addr_ & 0xFFu) < eeprom_.size()) {
                    eeprom_[addr_ & 0xFFu] = tx;
                    LOG(Periph, "[Sa1111Ssp] EEPROM write [0x%02X]=0x%02X\n",
                        addr_ & 0xFFu, tx);
                }
                addr_++;
                rx_ = 0xFF;
                break;
            case Phase::RdsrData:
                rx_ = wel_ ? 0x02u : 0x00u;
                break;
            case Phase::WrsrData:
                status_reg_ = tx;
                phase_ = Phase::Drain;
                rx_ = 0xFF;
                break;
            case Phase::Drain:
                rx_ = 0xFF;
                break;
        }
        rx_ready_ = true;
    }

    GuestCycleClock*     clock_ = nullptr;
    Sa1111Intc*          intc_  = nullptr;
    Sa1111SerialTransfer xfer_{emu_, "Sa1111Ssp", kSspClockHz, Sa1111SerialTransfer::kDefaultKeys,
                               [this](uint64_t now) { Settle(now); }};
    Levels               pub_;
    std::vector<uint8_t> eeprom_;
    uint32_t cr0_ = 0, cr1_ = 0;
    Phase    phase_ = Phase::Cmd;
    uint32_t addr_ = 0;
    uint8_t  rx_ = 0xFF;
    uint8_t  tx_ = 0;
    uint8_t  status_reg_ = 0;
    bool     rx_ready_ = false;
    bool     wel_ = false;
};

}

REGISTER_SERVICE(Sa1111Ssp);
