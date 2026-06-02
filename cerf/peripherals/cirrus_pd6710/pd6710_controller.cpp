#include "pd6710_controller.h"

#include "pd6710_card.h"
#include "pd6710_card_irq_line.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

constexpr uint32_t kBase = 0x110003E0u;
constexpr uint32_t kSize = 0x00FFFC20u;

constexpr uint32_t kOffsetIndex = 0x0u;
constexpr uint32_t kOffsetData  = 0x1u;

/* PD6710 internal register indices — names match pcmcia.sys
   conventions and the PD6710 datasheet. */
enum : uint8_t {
    kRegChipRevision              = 0x00,
    kRegInterfaceStatus           = 0x01,
    kRegPowerControl              = 0x02,
    kRegInterruptAndGeneralCtrl   = 0x03,
    kRegCardStatusChange          = 0x04,
    kRegStatusChangeIntConfig     = 0x05,
    kRegWindowEnable              = 0x06,
    kRegIoWindowControl           = 0x07,
    kRegIoMap0StartAddrLo         = 0x08,
    kRegIoMap0StartAddrHi         = 0x09,
    kRegIoMap0EndAddrLo           = 0x0A,
    kRegIoMap0EndAddrHi           = 0x0B,
    kRegIoMap1StartAddrLo         = 0x0C,
    kRegIoMap1StartAddrHi         = 0x0D,
    kRegIoMap1EndAddrLo           = 0x0E,
    kRegIoMap1EndAddrHi           = 0x0F,
    kRegMemMap0StartAddrLo        = 0x10,
    kRegMemMap0StartAddrHi        = 0x11,
    kRegMemMap0EndAddrLo          = 0x12,
    kRegMemMap0EndAddrHi          = 0x13,
    kRegMemMap0AddrOffsetLo       = 0x14,
    kRegMemMap0AddrOffsetHi       = 0x15,
    kRegGeneralControl            = 0x16,
    kRegFifoControl               = 0x17,
    kRegMemMap1StartAddrLo        = 0x18,
    kRegMemMap1StartAddrHi        = 0x19,
    kRegMemMap1EndAddrLo          = 0x1A,
    kRegMemMap1EndAddrHi          = 0x1B,
    kRegMemMap1AddrOffsetLo       = 0x1C,
    kRegMemMap1AddrOffsetHi       = 0x1D,
    kRegGlobalControl             = 0x1E,
    kRegChipInfo                  = 0x1F,
    kRegMemMap2StartAddrLo        = 0x20,
    kRegMemMap2StartAddrHi        = 0x21,
    kRegMemMap2EndAddrLo          = 0x22,
    kRegMemMap2EndAddrHi          = 0x23,
    kRegMemMap2AddrOffsetLo       = 0x24,
    kRegMemMap2AddrOffsetHi       = 0x25,
    kRegMemMap3StartAddrLo        = 0x28,
    kRegMemMap3StartAddrHi        = 0x29,
    kRegMemMap3EndAddrLo          = 0x2A,
    kRegMemMap3EndAddrHi          = 0x2B,
    kRegMemMap3AddrOffsetLo       = 0x2C,
    kRegMemMap3AddrOffsetHi       = 0x2D,
    kRegMemMap4StartAddrLo        = 0x30,
    kRegMemMap4StartAddrHi        = 0x31,
    kRegMemMap4EndAddrLo          = 0x32,
    kRegMemMap4EndAddrHi          = 0x33,
    kRegMemMap4AddrOffsetLo       = 0x34,
    kRegMemMap4AddrOffsetHi       = 0x35,
    kRegCardIoMap0OffsetLo        = 0x36,
    kRegCardIoMap0OffsetHi        = 0x37,
    kRegSetupTiming0              = 0x3A,
    kRegCmdTiming0                = 0x3B,
    kRegRecoveryTiming0           = 0x3C,
    kRegSetupTiming1              = 0x3D,
    kRegCmdTiming1                = 0x3E,
    kRegRecoveryTiming1           = 0x3F,
};

/* REG_INTERFACE_STATUS bits (PD6710 register set, matching the
   IOCONTROLPCMCIA bitfield union in the DeviceEmulator host runtime). */
constexpr uint8_t kIfsCd1       = 1u << 2;
constexpr uint8_t kIfsCd2       = 1u << 3;
constexpr uint8_t kIfsCardReady = 1u << 5;

/* REG_POWER_CONTROL: pcmcia.sys writes 0x90 to power the card on
   (bit 4 = VCC enable, bit 7 = output enable). The PD6710 reports
   STS_CARD_READY only when both bits are set. */
constexpr uint8_t kPowerOnPattern = 0x90;

/* REG_INTERRUPT_AND_GENERAL_CONTROL low nibble = CARD_IRQ_SEL[3:0].
   Non-zero means the card IRQ is enabled (any non-zero value routes
   the same way; the PD6710 datasheet documents this as the IRQ
   number, but on this board the routing always lands on EINT8). */
constexpr uint8_t kCardIrqSelectMask = 0x0F;

}  /* namespace */

bool Pd6710Controller::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    if (!bd) return false;
    const auto b = bd->GetBoard();
    return b == Board::Smdk2410DevEmu;
}

void Pd6710Controller::OnReady() {
    /* Power-on default: REG_CHIP_INFO starts at 0xC0 so the first
       read returns the top-two-bits-set form and subsequent reads
       return 0 until the register is written again. */
    reg_chip_info_ = 0xC0u;

    emu_.Get<PeripheralDispatcher>().Register(this);
}

Pd6710Card* Pd6710Controller::ResolveCard() const {
    if (!card_) card_ = emu_.TryGet<Pd6710Card>();
    return card_;
}

Pd6710CardIrqLine* Pd6710Controller::ResolveIrqLine() const {
    if (!irq_line_) irq_line_ = emu_.TryGet<Pd6710CardIrqLine>();
    return irq_line_;
}

uint32_t Pd6710Controller::MmioBase() const { return kBase; }
uint32_t Pd6710Controller::MmioSize() const { return kSize; }

uint8_t Pd6710Controller::ReadByte(uint32_t addr) {
    const uint32_t off = addr - kBase;
    if (off == kOffsetIndex) {
        std::lock_guard<std::mutex> lk(state_mutex_);
        LOG(Pcmcia, "[PD6710] read INDEX -> 0x%02X\n", index_);
        return index_;
    }
    if (off == kOffsetData) {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const uint8_t value = ReadIndexedData();
        LOG(Pcmcia, "[PD6710] read DATA[idx=0x%02X] -> 0x%02X\n",
            index_, value);
        return value;
    }
    LOG(Pcmcia, "[PD6710] read fallback +0x%X -> 0\n", off);
    return 0u;
}

uint16_t Pd6710Controller::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - kBase;
    LOG(Pcmcia, "[PD6710] read16 +0x%X (fallthrough) -> 0\n", off);
    return 0u;
}

void Pd6710Controller::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - kBase;
    if (off == kOffsetIndex) {
        std::lock_guard<std::mutex> lk(state_mutex_);
        index_ = value;
        LOG(Pcmcia, "[PD6710] write INDEX = 0x%02X\n", value);
        return;
    }
    if (off == kOffsetData) {
        std::lock_guard<std::mutex> lk(state_mutex_);
        LOG(Pcmcia, "[PD6710] write DATA[idx=0x%02X] = 0x%02X\n",
            index_, value);
        WriteIndexedData(value);
        return;
    }
    LOG(Pcmcia, "[PD6710] write fallback +0x%X = 0x%02X\n", off, value);
}

void Pd6710Controller::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - kBase;
    LOG(Pcmcia, "[PD6710] write16 +0x%X = 0x%04X (fallthrough)\n",
        off, value);
}

bool Pd6710Controller::IsCardInserted() const {
    return const_cast<Pd6710Controller*>(this)->ResolveCard() != nullptr;
}

bool Pd6710Controller::IsCardPowered() const {
    if (!IsCardInserted()) return false;
    std::lock_guard<std::mutex> lk(state_mutex_);
    return (reg_power_control_ & kPowerOnPattern) == kPowerOnPattern;
}

Pd6710Card* Pd6710Controller::Card() const {
    return const_cast<Pd6710Controller*>(this)->ResolveCard();
}

bool Pd6710Controller::MapIoAddress(uint32_t* io_offset) const {
    if (!IsCardPowered()) return false;

    if (*io_offset < 0xFF0000u) return false;
    const uint32_t addr = *io_offset - 0xFF0000u;

    std::lock_guard<std::mutex> lk(state_mutex_);

    /* REG_WINDOW_ENABLE: bit 6 = WIN_IO_MAP1_ENABLE, bit 7 =
       WIN_IO_MAP0_ENABLE (matching the IOCONTROLPCMCIA REG_WINDOW_ENABLE
       bitfield union in the DeviceEmulator host runtime). */
    constexpr uint8_t kWinIoMap0Enable = 1u << 6;
    constexpr uint8_t kWinIoMap1Enable = 1u << 7;

    auto u16 = [](uint8_t lo, uint8_t hi) -> uint32_t {
        return (uint32_t)lo | ((uint32_t)hi << 8);
    };

    if (reg_window_enable_ & kWinIoMap1Enable) {
        const uint32_t s = u16(reg_io_map1_start_lo_, reg_io_map1_start_hi_);
        const uint32_t e = u16(reg_io_map1_end_lo_,   reg_io_map1_end_hi_);
        if (addr >= s && addr <= e) {
            *io_offset = addr - s;
            return true;
        }
    }
    if (reg_window_enable_ & kWinIoMap0Enable) {
        const uint32_t s = u16(reg_io_map0_start_lo_, reg_io_map0_start_hi_);
        const uint32_t e = u16(reg_io_map0_end_lo_,   reg_io_map0_end_hi_);
        if (addr >= s && addr <= e) {
            *io_offset = addr - s;
            return true;
        }
    }
    return false;
}

void Pd6710Controller::RaiseCardIrq() {
    bool enabled;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        enabled = (reg_interrupt_and_gen_ctrl_ & kCardIrqSelectMask) != 0u;
    }
    if (!enabled) return;
    if (auto* line = ResolveIrqLine()) line->Assert();
}

void Pd6710Controller::ClearCardIrq() {
    bool enabled;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        enabled = (reg_interrupt_and_gen_ctrl_ & kCardIrqSelectMask) != 0u;
    }
    if (!enabled) return;
    if (auto* line = ResolveIrqLine()) line->Deassert();
}

uint8_t Pd6710Controller::ReadIndexedData() {
    switch (index_) {
    case kRegChipRevision:
        return 0x83u;  /* pcmcia.sys expects this revision */

    case kRegInterfaceStatus: {
        /* Report CD1 + CD2 + (CARD_READY when powered) when a card
           is in the socket. With no card forced clear. */
        constexpr uint8_t kFloatingBits = (kIfsCd1 | kIfsCd2 | kIfsCardReady);
        uint8_t masked =
            static_cast<uint8_t>(reg_interface_status_ & ~kFloatingBits);
        if (IsCardInserted()) {
            masked |= (kIfsCd1 | kIfsCd2);
            if ((reg_power_control_ & kPowerOnPattern) == kPowerOnPattern) {
                masked |= kIfsCardReady;
            }
        }
        return masked;
    }

    case kRegPowerControl:              return reg_power_control_;
    case kRegInterruptAndGeneralCtrl:   return reg_interrupt_and_gen_ctrl_;

    case kRegCardStatusChange: {
        const uint8_t value = reg_card_status_change_;
        reg_card_status_change_ = 0u;
        return value;
    }

    case kRegStatusChangeIntConfig:     return reg_status_change_int_cfg_;
    case kRegWindowEnable:              return reg_window_enable_;
    case kRegIoWindowControl:           return reg_io_window_control_;

    case kRegMemMap0StartAddrLo:
    case kRegMemMap0StartAddrHi:        return 0u;

    case kRegGeneralControl:            return 1u;  /* 5.0V → 16-bit card */
    case kRegFifoControl:               return 0u;

    case kRegMemMap1StartAddrLo:
    case kRegMemMap1StartAddrHi:        return 0u;

    case kRegGlobalControl:             return 0u;

    case kRegChipInfo: {
        const uint8_t value = reg_chip_info_;
        reg_chip_info_ = static_cast<uint8_t>(reg_chip_info_ & ~0xC0u);
        return value;
    }

    case kRegMemMap2StartAddrLo:
    case kRegMemMap2StartAddrHi:
    case kRegMemMap3StartAddrLo:
    case kRegMemMap3StartAddrHi:
    case kRegMemMap4StartAddrLo:
    case kRegMemMap4StartAddrHi:        return 0u;

    case kRegIoMap0StartAddrLo: return reg_io_map0_start_lo_;
    case kRegIoMap0StartAddrHi: return reg_io_map0_start_hi_;
    case kRegIoMap0EndAddrLo:   return reg_io_map0_end_lo_;
    case kRegIoMap0EndAddrHi:   return reg_io_map0_end_hi_;
    case kRegIoMap1StartAddrLo: return reg_io_map1_start_lo_;
    case kRegIoMap1StartAddrHi: return reg_io_map1_start_hi_;
    case kRegIoMap1EndAddrLo:   return reg_io_map1_end_lo_;
    case kRegIoMap1EndAddrHi:   return reg_io_map1_end_hi_;

    default:
        LOG(Caution, "[PD6710] unsupported INDEX 0x%02X on read\n", index_);
        return 0u;
    }
}

void Pd6710Controller::WriteIndexedData(uint8_t value) {
    switch (index_) {
    case kRegPowerControl: {
        const bool was_powered =
            (reg_power_control_ & kPowerOnPattern) == kPowerOnPattern;
        reg_power_control_ = value;
        const bool now_powered =
            (reg_power_control_ & kPowerOnPattern) == kPowerOnPattern;
        if (now_powered != was_powered) {
            if (auto* c = ResolveCard()) {
                if (now_powered) c->PowerOn();
                else             c->PowerOff();
            }
        }
        return;
    }

    case kRegInterruptAndGeneralCtrl:   reg_interrupt_and_gen_ctrl_ = value; return;
    case kRegStatusChangeIntConfig:     reg_status_change_int_cfg_  = value; return;
    case kRegWindowEnable:              reg_window_enable_          = value; return;
    case kRegIoWindowControl:           reg_io_window_control_      = value; return;

    case kRegIoMap0StartAddrLo: reg_io_map0_start_lo_ = value; return;
    case kRegIoMap0StartAddrHi: reg_io_map0_start_hi_ = value; return;
    case kRegIoMap0EndAddrLo:   reg_io_map0_end_lo_   = value; return;
    case kRegIoMap0EndAddrHi:   reg_io_map0_end_hi_   = value; return;
    case kRegIoMap1StartAddrLo: reg_io_map1_start_lo_ = value; return;
    case kRegIoMap1StartAddrHi: reg_io_map1_start_hi_ = value; return;
    case kRegIoMap1EndAddrLo:   reg_io_map1_end_lo_   = value; return;
    case kRegIoMap1EndAddrHi:   reg_io_map1_end_hi_   = value; return;

    case kRegMemMap0StartAddrLo:
    case kRegMemMap0StartAddrHi:
    case kRegMemMap0EndAddrLo:
    case kRegMemMap0EndAddrHi:
    case kRegMemMap0AddrOffsetLo:
    case kRegMemMap0AddrOffsetHi:        return;

    case kRegGeneralControl:
    case kRegFifoControl:
    case kRegGlobalControl:              return;

    case kRegChipInfo:
        reg_chip_info_ = 0xC0u;
        return;

    case kRegMemMap1StartAddrLo:
    case kRegMemMap1StartAddrHi:
    case kRegMemMap1EndAddrLo:
    case kRegMemMap1EndAddrHi:
    case kRegMemMap1AddrOffsetLo:
    case kRegMemMap1AddrOffsetHi:
    case kRegMemMap2StartAddrLo:
    case kRegMemMap2StartAddrHi:
    case kRegMemMap2EndAddrLo:
    case kRegMemMap2EndAddrHi:
    case kRegMemMap2AddrOffsetLo:
    case kRegMemMap2AddrOffsetHi:
    case kRegMemMap3StartAddrLo:
    case kRegMemMap3StartAddrHi:
    case kRegMemMap3EndAddrLo:
    case kRegMemMap3EndAddrHi:
    case kRegMemMap3AddrOffsetLo:
    case kRegMemMap3AddrOffsetHi:
    case kRegMemMap4StartAddrLo:
    case kRegMemMap4StartAddrHi:
    case kRegMemMap4EndAddrLo:
    case kRegMemMap4EndAddrHi:
    case kRegMemMap4AddrOffsetLo:
    case kRegMemMap4AddrOffsetHi:
    case kRegCardIoMap0OffsetLo:
    case kRegCardIoMap0OffsetHi:
    case kRegSetupTiming0:
    case kRegCmdTiming0:
    case kRegRecoveryTiming0:
    case kRegSetupTiming1:
    case kRegCmdTiming1:
    case kRegRecoveryTiming1:           return;

    default:
        LOG(Caution, "[PD6710] unsupported INDEX 0x%02X on write "
                "(value 0x%02X)\n", index_, value);
        return;
    }
}

REGISTER_SERVICE(Pd6710Controller);
