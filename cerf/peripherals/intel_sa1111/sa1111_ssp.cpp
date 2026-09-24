#include "../peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../core/cerf_paths.h"
#include "../../core/string_utils.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <fstream>
#include <vector>

namespace {

/* SA-1111 SSP (Developer's Manual §8, base 0x40000800): SSPCR0 +0x00,
   SSPCR1 +0x04, SSPSR +0x10 (TNF bit2 / RNE bit3 / BSY bit4, §8.6.4 -
   hplib.dll sub_EA1C40 polls all three; TNF reading 0 wedges it), SSPDR
   +0x40. EEPROM opcodes per sub_EA1C40; writes stay in-memory. */
class Sa1111Ssp : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Jornada720;
    }

    void OnReady() override {
        const auto& cfg = emu_.Get<DeviceConfig>();
        if (!cfg.rom_eeprom.empty()) {
            const std::string path = ResolveDeviceFile(cfg.device_name,
                                                       cfg.rom_eeprom);
            std::ifstream f(path, std::ios::binary | std::ios::ate);
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
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0x40000800u; }
    uint32_t MmioSize() const override { return 0x00000200u; }

    uint32_t ReadWord(uint32_t addr) override {
        return ReadReg(addr - MmioBase());
    }
    uint8_t ReadByte(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        return (uint8_t)(ReadReg(off & ~0x3u) >> ((off & 0x3u) * 8u));
    }
    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        return (uint16_t)(ReadReg(off & ~0x3u) >> ((off & 0x2u) * 8u));
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        WriteReg(addr - MmioBase(), value);
    }
    void WriteByte(uint32_t addr, uint8_t value) override {
        const uint32_t off = addr - MmioBase();
        /* SSPDR byte write = one frame; control regs merge into the lane. */
        if ((off & ~0x3u) == 0x40u) { ClockByte(value); return; }
        const uint32_t shift = (off & 0x3u) * 8u;
        const uint32_t cur   = ReadReg(off & ~0x3u);
        WriteReg(off & ~0x3u,
                 (cur & ~(0xFFu << shift)) | ((uint32_t)value << shift));
    }

    void SaveState(StateWriter& w) override {
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
    }

private:
    enum class Phase { Cmd, ReadAddr, ReadData, WriteAddr, WriteData,
                       RdsrData, WrsrData, Drain };

    uint32_t ReadReg(uint32_t off) {
        switch (off) {
            case 0x00: return cr0_;
            case 0x04: return cr1_;
            case 0x10: return 0x4u | (rx_ready_ ? 0x8u : 0u);  /* TNF set, RNE iff a byte is waiting, BSY clear. */
            case 0x40: rx_ready_ = false; return rx_;
        }
        HaltUnsupportedAccess("ReadReg", MmioBase() + off, 0);
    }

    void WriteReg(uint32_t off, uint32_t value) {
        switch (off) {
            case 0x00: cr0_ = value; EndTransaction(); return;  /* (re)configure = new transaction. */
            case 0x04: cr1_ = value; return;
            case 0x10: rx_ready_ = false; return;               /* status clear. */
            case 0x40: ClockByte(static_cast<uint8_t>(value)); return;
        }
        HaltUnsupportedAccess("WriteReg", MmioBase() + off, value);
    }

    /* Command/deselect boundary: WEL survives WREN's own cycle but clears
       once a write cycle completes (25xx WRITE auto-disables the latch). */
    void EndTransaction() {
        if (phase_ == Phase::WriteData) wel_ = false;
        phase_ = Phase::Cmd;
    }

    uint8_t EepromByte(uint32_t a) const {
        return a < eeprom_.size() ? eeprom_[a] : 0xFFu;
    }

    /* Full-duplex SPI: a TX byte clocks one response byte out of the EEPROM.
       Opcodes per hplib.dll sub_EA1C40 (the guest-side command engine). */
    void ClockByte(uint8_t tx) {
        switch (phase_) {
            case Phase::Cmd:
                rx_ = 0xFF;
                switch (tx) {
                    case 0x01: phase_ = Phase::WrsrData; break;  /* WRSR */
                    case 0x02: phase_ = Phase::WriteAddr; break; /* WRITE */
                    case 0x03: phase_ = Phase::ReadAddr; break;  /* READ */
                    case 0x04: wel_ = false; break;              /* WRDI */
                    case 0x05: phase_ = Phase::RdsrData; break;  /* RDSR */
                    case 0x06: wel_ = true; break;               /* WREN */
                    default:
                        LOG(Caution, "Sa1111Ssp: unhandled EEPROM command "
                            "0x%02X - responding 0xFF\n", tx);
                        phase_ = Phase::Drain;
                        break;
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
                rx_ = wel_ ? 0x02u : 0x00u;   /* WEL bit1, WIP bit0 clear. */
                break;
            case Phase::WrsrData:
                status_reg_ = tx;             /* block-protect bits, no effect. */
                phase_ = Phase::Drain;
                rx_ = 0xFF;
                break;
            case Phase::Drain:
                rx_ = 0xFF;
                break;
        }
        rx_ready_ = true;
    }

    std::vector<uint8_t> eeprom_;
    uint32_t cr0_ = 0, cr1_ = 0;
    Phase    phase_ = Phase::Cmd;
    uint32_t addr_ = 0;
    uint8_t  rx_ = 0xFF;
    uint8_t  status_reg_ = 0;
    bool     rx_ready_ = false;
    bool     wel_ = false;
};

}  /* namespace */

REGISTER_SERVICE(Sa1111Ssp);
