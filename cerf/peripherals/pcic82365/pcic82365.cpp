#include "pcic82365.h"

#include "../../state/state_stream.h"

namespace {

enum : uint8_t {
    kRegInterfaceStatus       = 0x01,
    kRegPowerControl          = 0x02,
    kRegInterruptAndGeneral   = 0x03,
    kRegCardStatusChange      = 0x04,
    kRegStatusChangeIntConfig = 0x05,
    kRegWindowEnable          = 0x06,
    kRegIoWindowControl       = 0x07,
    kRegIoMapFirst            = 0x08,
    kRegIoMapLast             = 0x0F,
    kRegMemMapFirst           = 0x10,
    kRegMemMapLast            = 0x35,
    kRegIoOffsetFirst         = 0x36,
    kRegIoOffsetLast          = 0x39,
    kRegTimingFirst           = 0x3A,
    kRegTimingLast            = 0x3F,
    kRegMemPageFirst          = 0x40,   /* MEM_MAP0..4 window-page (extended PCIC) */
    kRegMemPageLast           = 0x44,
};

/* REG_INTERFACE_STATUS bits (i82365reg.h PCIC_IF_STATUS_*). */
constexpr uint8_t kIfsCd1       = 0x04u;
constexpr uint8_t kIfsCd2       = 0x08u;
constexpr uint8_t kIfsCardReady = 0x20u;

/* REG_INTERRUPT_AND_GENERAL_CONTROL CARDTYPE (i82365reg.h PCIC_INTR_CARDTYPE_IO). */
constexpr uint8_t kIntrCardTypeIo = 0x20u;

/* PWR_VCC_BIT1 | PWR_OUTPUT_ENABLE - the powered-on pattern the BSP driver writes. */
constexpr uint8_t kPowerOnPattern = 0x90u;

constexpr uint8_t kWinIoMap0Enable = 0x40u;
constexpr uint8_t kWinIoMap1Enable = 0x80u;

constexpr uint8_t kMohRegActive    = 0x40u;
constexpr uint8_t kMohWriteProtect = 0x80u;

bool IsMemMapReg(uint8_t index) {
    return index >= kRegMemMapFirst && index <= kRegMemMapLast &&
           (index & 7u) <= 5u;
}

}  /* namespace */

bool Pcic82365::CardPoweredByReg() const {
    return (reg_power_control_ & kPowerOnPattern) == kPowerOnPattern;
}

bool Pcic82365::Owns(uint8_t index) {
    if (index >= kRegInterfaceStatus && index <= kRegIoMapLast) return true;
    if (IsMemMapReg(index)) return true;
    if (index >= kRegIoOffsetFirst && index <= kRegIoOffsetLast) return true;
    if (index >= kRegTimingFirst && index <= kRegTimingLast) return true;
    if (index >= kRegMemPageFirst && index <= kRegMemPageLast) return true;
    return false;
}

uint8_t Pcic82365::ReadReg(uint8_t index) {
    if (IsMemMapReg(index)) {
        return mem_reg_[(index - kRegMemMapFirst) >> 3][index & 7u];
    }
    if (index >= kRegIoMapFirst && index <= kRegIoMapLast) {
        const int win = (index - kRegIoMapFirst) >= 4 ? 1 : 0;
        switch ((index - kRegIoMapFirst) & 3u) {
            case 0: return io_start_lo_[win];
            case 1: return io_start_hi_[win];
            case 2: return io_end_lo_[win];
            case 3: return io_end_hi_[win];
        }
    }
    if (index >= kRegIoOffsetFirst && index <= kRegIoOffsetLast) {
        const int win = (index - kRegIoOffsetFirst) >= 2 ? 1 : 0;
        return ((index - kRegIoOffsetFirst) & 1u) ? io_off_hi_[win]
                                                  : io_off_lo_[win];
    }
    if (index >= kRegTimingFirst && index <= kRegTimingLast) {
        return timing_[index - kRegTimingFirst];
    }
    if (index >= kRegMemPageFirst && index <= kRegMemPageLast) {
        return mem_page_[index - kRegMemPageFirst];
    }

    switch (index) {
        case kRegInterfaceStatus: {
            uint8_t v = 0u;
            if (card_present_) {
                v |= kIfsCd1 | kIfsCd2;
                const bool io_card = (reg_interrupt_and_gen_ctrl_ & kIntrCardTypeIo) != 0u;
                if (CardPoweredByReg() && !(io_card && card_irq_)) v |= kIfsCardReady;
            }
            return v;
        }
        case kRegPowerControl:          return reg_power_control_;
        case kRegInterruptAndGeneral:   return reg_interrupt_and_gen_ctrl_;
        case kRegCardStatusChange: {
            const uint8_t v = reg_card_status_change_;
            reg_card_status_change_ = 0u;   /* read clears */
            return v;
        }
        case kRegStatusChangeIntConfig: return reg_status_change_int_cfg_;
        case kRegWindowEnable:          return reg_window_enable_;
        case kRegIoWindowControl:       return reg_io_window_control_;
        default:                        return 0u;
    }
}

bool Pcic82365::WriteReg(uint8_t index, uint8_t value, bool* power_on) {
    if (IsMemMapReg(index)) {
        mem_reg_[(index - kRegMemMapFirst) >> 3][index & 7u] = value;
        return false;
    }
    if (index >= kRegIoMapFirst && index <= kRegIoMapLast) {
        const int win = (index - kRegIoMapFirst) >= 4 ? 1 : 0;
        switch ((index - kRegIoMapFirst) & 3u) {
            case 0: io_start_lo_[win] = value; break;
            case 1: io_start_hi_[win] = value; break;
            case 2: io_end_lo_[win]   = value; break;
            case 3: io_end_hi_[win]   = value; break;
        }
        return false;
    }
    if (index >= kRegIoOffsetFirst && index <= kRegIoOffsetLast) {
        const int win = (index - kRegIoOffsetFirst) >= 2 ? 1 : 0;
        if ((index - kRegIoOffsetFirst) & 1u) io_off_hi_[win] = value;
        else                                  io_off_lo_[win] = value;
        return false;
    }
    if (index >= kRegTimingFirst && index <= kRegTimingLast) {
        timing_[index - kRegTimingFirst] = value;
        return false;
    }
    if (index >= kRegMemPageFirst && index <= kRegMemPageLast) {
        mem_page_[index - kRegMemPageFirst] = value;
        return false;
    }

    switch (index) {
        case kRegPowerControl: {
            const bool was = CardPoweredByReg();
            reg_power_control_ = value;
            const bool now = CardPoweredByReg();
            *power_on = now;
            return now != was;
        }
        case kRegInterruptAndGeneral:   reg_interrupt_and_gen_ctrl_ = value; return false;
        case kRegStatusChangeIntConfig: reg_status_change_int_cfg_  = value; return false;
        case kRegWindowEnable:          reg_window_enable_          = value; return false;
        case kRegIoWindowControl:       reg_io_window_control_      = value; return false;
        default:                        return false;   /* interface-status / csc: not writable */
    }
}

bool Pcic82365::MapIo(uint32_t bus_io, uint32_t* card_io) const {
    auto u16 = [](uint8_t lo, uint8_t hi) -> uint32_t {
        return static_cast<uint32_t>(lo) | (static_cast<uint32_t>(hi) << 8);
    };
    for (int win : {1, 0}) {
        const uint8_t enable_bit = (win == 1) ? kWinIoMap1Enable : kWinIoMap0Enable;
        if (!(reg_window_enable_ & enable_bit)) continue;
        const uint32_t start = u16(io_start_lo_[win], io_start_hi_[win]);
        const uint32_t end   = u16(io_end_lo_[win],   io_end_hi_[win]);
        if (bus_io < start || bus_io > end) continue;
        const uint32_t offset = u16(io_off_lo_[win], io_off_hi_[win]) & 0xFFFEu;
        *card_io = (bus_io + offset) & 0xFFFFu;
        return true;
    }
    return false;
}

bool Pcic82365::MapMem(uint32_t bus_off, uint32_t* card_addr,
                       bool* attribute, bool* writable) const {
    const uint32_t host_page = bus_off >> 12;
    for (int win = 0; win < 5; ++win) {
        if (!(reg_window_enable_ & (1u << win))) continue;
        const uint8_t* r = mem_reg_[win];
        const uint32_t pg    = static_cast<uint32_t>(mem_page_[win]) << 12;
        const uint32_t start = pg | static_cast<uint32_t>(r[0]) | (static_cast<uint32_t>(r[1] & 0x0Fu) << 8);
        const uint32_t end   = pg | static_cast<uint32_t>(r[2]) | (static_cast<uint32_t>(r[3] & 0x0Fu) << 8);
        if (host_page < start || host_page > end) continue;
        const uint32_t offset = static_cast<uint32_t>(r[4]) | (static_cast<uint32_t>(r[5] & 0x3Fu) << 8);
        *card_addr = (bus_off + (offset << 12)) & 0x3FFFFFFu;
        *attribute = (r[5] & kMohRegActive)    != 0u;
        *writable  = (r[5] & kMohWriteProtect) == 0u;
        return true;
    }
    return false;
}

void Pcic82365::SaveState(StateWriter& w) const {
    w.Write<uint8_t>("card_irq", card_irq_ ? 1u : 0u);
    w.Write("reg_power_control", reg_power_control_); w.Write("reg_interrupt_and_gen_ctrl", reg_interrupt_and_gen_ctrl_);
    w.Write("reg_card_status_change", reg_card_status_change_); w.Write("reg_status_change_int_cfg", reg_status_change_int_cfg_);
    w.Write("reg_window_enable", reg_window_enable_); w.Write("reg_io_window_control", reg_io_window_control_);
    w.WriteBytes("io_start_lo", io_start_lo_, sizeof(io_start_lo_));
    w.WriteBytes("io_start_hi", io_start_hi_, sizeof(io_start_hi_));
    w.WriteBytes("io_end_lo", io_end_lo_, sizeof(io_end_lo_));
    w.WriteBytes("io_end_hi", io_end_hi_, sizeof(io_end_hi_));
    w.WriteBytes("io_off_lo", io_off_lo_, sizeof(io_off_lo_));
    w.WriteBytes("io_off_hi", io_off_hi_, sizeof(io_off_hi_));
    w.WriteBytes("mem_reg", mem_reg_, sizeof(mem_reg_));
    w.WriteBytes("mem_page", mem_page_, sizeof(mem_page_));
    w.WriteBytes("timing", timing_, sizeof(timing_));
}

void Pcic82365::RestoreState(StateReader& r) {
    uint8_t irq = 0u; r.Read("card_irq", irq); card_irq_ = (irq != 0u);
    r.Read("reg_power_control", reg_power_control_); r.Read("reg_interrupt_and_gen_ctrl", reg_interrupt_and_gen_ctrl_);
    r.Read("reg_card_status_change", reg_card_status_change_); r.Read("reg_status_change_int_cfg", reg_status_change_int_cfg_);
    r.Read("reg_window_enable", reg_window_enable_); r.Read("reg_io_window_control", reg_io_window_control_);
    r.ReadBytes("io_start_lo", io_start_lo_, sizeof(io_start_lo_));
    r.ReadBytes("io_start_hi", io_start_hi_, sizeof(io_start_hi_));
    r.ReadBytes("io_end_lo", io_end_lo_, sizeof(io_end_lo_));
    r.ReadBytes("io_end_hi", io_end_hi_, sizeof(io_end_hi_));
    r.ReadBytes("io_off_lo", io_off_lo_, sizeof(io_off_lo_));
    r.ReadBytes("io_off_hi", io_off_hi_, sizeof(io_off_hi_));
    r.ReadBytes("mem_reg", mem_reg_, sizeof(mem_reg_));
    r.ReadBytes("mem_page", mem_page_, sizeof(mem_page_));
    r.ReadBytes("timing", timing_, sizeof(timing_));
}
