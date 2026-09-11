#include "siemens_mp377_sm501_ac97.h"

#include "siemens_mp377_sm501_internal.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../peripherals/cirrus_cs4297a/cs4297a_codec.h"
#include "../../socs/guest_cpu_reset.h"

namespace siemens_mp377 {

bool SiemensMp377Sm501Ac97::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetBoard() == Board::SiemensMP377;
}

void SiemensMp377Sm501Ac97::OnReady() {
    ResetController();
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) return;
        ResetController();
    });
}

bool SiemensMp377Sm501Ac97::IsRegister(uint32_t offset) {
    return IsTxRegister(offset) || IsRxRegister(offset) || offset == kControlStatusReg;
}

bool SiemensMp377Sm501Ac97::IsTxRegister(uint32_t offset) {
    return offset == kTxSlot0TagReg || offset == kTxSlot1CmdAddrReg || offset == kTxSlot2CmdDataReg ||
           offset == kTxSlot3PcmLeftReg || offset == kTxSlot4PcmRightReg;
}

bool SiemensMp377Sm501Ac97::IsRxRegister(uint32_t offset) {
    return offset == kRxSlot0TagReg || offset == kRxSlot1StatusAddrReg || offset == kRxSlot2StatusDataReg ||
           offset == kRxSlot3PcmLeftReg || offset == kRxSlot4PcmRightReg;
}

void SiemensMp377Sm501Ac97::ResetController() {
    std::lock_guard<std::recursive_mutex> lock(state_mutex_);
    ResetCodec(true);
    control_ = 0u;
    tx_slot0_ = tx_slot1_ = tx_slot2_ = tx_slot3_ = tx_slot4_ = 0u;
    rx_slot0_ = rx_slot1_ = rx_slot2_ = rx_slot3_ = rx_slot4_ = 0u;
    drop_count_ = 0u;
    irq_pending_ = false;
    codec_ready_ = false;
    bclk_running_ = false;
    tx_dirty_mask_ = 0u;
    frame_phase_ = 0u;
    codec_ready_frames_ = 0u;
    codec_read_pending_ = false;
    codec_read_register_ = 0u;
    codec_read_data_ = 0u;
    auto& registers = Registers();
    registers.regs_[kTxSlot0TagReg / 4u] = 0u;
    registers.regs_[kTxSlot1CmdAddrReg / 4u] = 0u;
    registers.regs_[kTxSlot2CmdDataReg / 4u] = 0u;
    registers.regs_[kTxSlot3PcmLeftReg / 4u] = 0u;
    registers.regs_[kTxSlot4PcmRightReg / 4u] = 0u;
    registers.regs_[kRxSlot0TagReg / 4u] = 0u;
    registers.regs_[kRxSlot1StatusAddrReg / 4u] = 0u;
    registers.regs_[kRxSlot2StatusDataReg / 4u] = 0u;
    registers.regs_[kRxSlot3PcmLeftReg / 4u] = 0u;
    registers.regs_[kRxSlot4PcmRightReg / 4u] = 0u;
    registers.regs_[kControlStatusReg / 4u] = 0u;
}

uint32_t SiemensMp377Sm501Ac97::Read(uint32_t off, bool clear_irq) {
    std::lock_guard<std::recursive_mutex> lock(state_mutex_);
    UpdateStatus();
    uint32_t value = 0;
    switch (off) {
    case kTxSlot0TagReg: value = tx_slot0_; break;
    case kTxSlot1CmdAddrReg: value = tx_slot1_; break;
    case kTxSlot2CmdDataReg: value = tx_slot2_; break;
    case kTxSlot3PcmLeftReg: value = tx_slot3_; break;
    case kTxSlot4PcmRightReg: value = tx_slot4_; break;
    case kRxSlot0TagReg: value = rx_slot0_; break;
    case kRxSlot1StatusAddrReg: value = rx_slot1_; break;
    case kRxSlot2StatusDataReg: value = rx_slot2_; break;
    case kRxSlot3PcmLeftReg: value = rx_slot3_; break;
    case kRxSlot4PcmRightReg: value = rx_slot4_; break;
    case kControlStatusReg:
        value = ControlStatusValue();
        if (clear_irq) ClearInterrupt();
        break;
    default: emu_.Get<Fatal>().Die("[MP377 SM501 AC97] read of unmodelled register 0x%X", off);
    }
    Registers().regs_[off / 4u] = value;
    return value;
}

void SiemensMp377Sm501Ac97::Write(uint32_t off, uint32_t old_value, uint32_t value) {
    std::lock_guard<std::recursive_mutex> lock(state_mutex_);
    switch (off) {
    case kTxSlot0TagReg:
        tx_slot0_ = value & 0x0000F800u;
        Registers().regs_[off / 4u] = tx_slot0_;
        NoteTxSlotWrite(kDirtyTag);
        break;
    case kTxSlot1CmdAddrReg:
        tx_slot1_ = value & (kCmdReadBit | kCmdIndexMask);
        Registers().regs_[off / 4u] = tx_slot1_;
        NoteTxSlotWrite(kDirtySlot1);
        break;
    case kTxSlot2CmdDataReg:
        tx_slot2_ = value & kCmdDataMask;
        Registers().regs_[off / 4u] = tx_slot2_;
        NoteTxSlotWrite(kDirtySlot2);
        break;
    case kTxSlot3PcmLeftReg:
        tx_slot3_ = value & kSlotDataMask;
        Registers().regs_[off / 4u] = tx_slot3_;
        NoteTxSlotWrite(kDirtySlot3);
        break;
    case kTxSlot4PcmRightReg:
        tx_slot4_ = value & kSlotDataMask;
        Registers().regs_[off / 4u] = tx_slot4_;
        NoteTxSlotWrite(kDirtySlot4);
        break;
    case kRxSlot0TagReg:
    case kRxSlot1StatusAddrReg:
    case kRxSlot2StatusDataReg:
    case kRxSlot3PcmLeftReg:
    case kRxSlot4PcmRightReg: Registers().regs_[off / 4u] = old_value; break;
    case kControlStatusReg: {
        const uint32_t writable = kCtrlEnable | kCtrlColdReset | kCtrlWarmReset | kCtrlWakeIrqEnable | kCtrlStopSync;
        control_ = value & writable;
        if ((value & kCtrlColdReset) != 0u) {
            ResetCodec(true);
        } else if ((value & kCtrlWarmReset) != 0u) {
            emu_.Get<Cs4297aCodec>().WarmReset();
            codec_ready_ = false;
            codec_ready_frames_ = 0u;
            codec_read_pending_ = false;
        }
        UpdateStatus();
        Registers().regs_[off / 4u] = ControlStatusValue();
        break;
    }
    default: emu_.Get<Fatal>().Die("[MP377 SM501 AC97] write of unmodelled register 0x%X = 0x%08X", off, value);
    }
}

uint8_t SiemensMp377Sm501Ac97::ReadByte(uint32_t off, bool clear_irq) {
    std::lock_guard<std::recursive_mutex> lock(state_mutex_);
    const uint32_t word = Read(off & ~3u, clear_irq && ((off & ~3u) == kControlStatusReg));
    return static_cast<uint8_t>(word >> ((off & 3u) * 8u));
}

void SiemensMp377Sm501Ac97::WriteByte(uint32_t off, uint8_t value) {
    std::lock_guard<std::recursive_mutex> lock(state_mutex_);
    const uint32_t word_off = off & ~3u;
    const uint32_t byte = off & 3u;
    const uint32_t shift = byte * 8u;

    auto patch_word = [&](uint32_t current) -> uint32_t {
        return (current & ~(0xFFu << shift)) | (static_cast<uint32_t>(value) << shift);
    };

    switch (word_off) {
    case kControlStatusReg:
        if (byte == 0u) {
            const uint32_t low_control = static_cast<uint32_t>(value) &
                                         (kCtrlEnable | kCtrlColdReset | kCtrlWarmReset |
                                          kCtrlWakeIrqEnable);
            Write(word_off, Registers().regs_[word_off / 4u],
                  (control_ & kCtrlStopSync) | low_control);
        } else if (byte == 1u) {
            /* SM501 MMCC Databook v1.02, AC97 Control & Status: in the
               8051 high byte only bit 1 (full-register bit 9) is writable.
               BCLK and the dropped-frame count are read-only. */
            control_ = (control_ & ~kCtrlStopSync) |
                       ((static_cast<uint32_t>(value) & 0x02u) << 8u);
            UpdateStatus();
        }
        return;
    case kTxSlot0TagReg:
        tx_slot0_ = patch_word(tx_slot0_) & 0x0000F800u;
        Registers().regs_[word_off / 4u] = tx_slot0_;
        if (byte == 1u) NoteTxSlotWrite(kDirtyTag);
        return;
    case kTxSlot1CmdAddrReg:
        tx_slot1_ = patch_word(tx_slot1_) & (kCmdReadBit | kCmdIndexMask);
        Registers().regs_[word_off / 4u] = tx_slot1_;
        if (byte == 2u) NoteTxSlotWrite(kDirtySlot1);
        return;
    case kTxSlot2CmdDataReg:
        tx_slot2_ = patch_word(tx_slot2_) & kCmdDataMask;
        Registers().regs_[word_off / 4u] = tx_slot2_;
        if (byte == 2u) NoteTxSlotWrite(kDirtySlot2);
        return;
    case kTxSlot3PcmLeftReg:
        tx_slot3_ = patch_word(tx_slot3_) & kSlotDataMask;
        Registers().regs_[word_off / 4u] = tx_slot3_;
        if (byte == 2u) NoteTxSlotWrite(kDirtySlot3);
        return;
    case kTxSlot4PcmRightReg:
        tx_slot4_ = patch_word(tx_slot4_) & kSlotDataMask;
        Registers().regs_[word_off / 4u] = tx_slot4_;
        if (byte == 2u) NoteTxSlotWrite(kDirtySlot4);
        return;
    default: {
        uint32_t word = Read(word_off, false);
        word = patch_word(word);
        Write(word_off, Registers().regs_[word_off / 4u], word);
        return;
    }
    }
}

uint32_t SiemensMp377Sm501Ac97::ControlStatusValue() const {
    uint32_t status = control_ & (kCtrlEnable | kCtrlColdReset | kCtrlWarmReset | kCtrlWakeIrqEnable | kCtrlStopSync);
    status |= (drop_count_ & 0x3Fu) << 10;
    if (bclk_running_) status |= kCtrlBclkRunning;

    uint32_t st = 0;
    if ((control_ & kCtrlEnable) == 0u)
        st = 0;
    else if ((control_ & (kCtrlColdReset | kCtrlWarmReset)) != 0u)
        st = 1;
    else if (!codec_ready_ || !LinkPowered() || (control_ & kCtrlStopSync) != 0u)
        st = 2;
    else
        st = 3;
    status |= st << kCtrlStatusShift;
    return status;
}

void SiemensMp377Sm501Ac97::UpdateStatus() {
    std::lock_guard<std::recursive_mutex> lock(state_mutex_);
    auto& power = emu_.Get<SiemensMp377Sm501PowerGpio>();
    const bool gate_on = power.IsGateEnabled(kSm501GateAc97I2sBit);
    const bool enabled = (control_ & kCtrlEnable) != 0u;
    const bool reset = (control_ & (kCtrlColdReset | kCtrlWarmReset)) != 0u;
    const bool sync_stopped = (control_ & kCtrlStopSync) != 0u;
    const bool link_powered = LinkPowered();
    const bool pins_routed = power.IsAc97LinkMuxed();
    const bool board_reset_released = power.IsCodecResetDeasserted();

    const bool link_clock_running = gate_on && enabled && !reset && !sync_stopped && link_powered &&
                                    pins_routed && board_reset_released;
    if (!link_clock_running) {
        codec_ready_ = false;
        codec_ready_frames_ = 0u;
        codec_read_pending_ = false;
    }
    bclk_running_ = link_clock_running;
    /* SM501 MMCC Databook v1.02, AC97 RX Slot 0 Tag Port: bit 15 is
       Codec Ready; bits 14:11 independently report valid receive slots. */
    rx_slot0_ &= ~kTagValidFrame;
    if (codec_ready_ && link_powered) rx_slot0_ |= kTagValidFrame;
    Registers().regs_[kRxSlot0TagReg / 4u] = rx_slot0_;
    Registers().regs_[kControlStatusReg / 4u] = ControlStatusValue();
}

void SiemensMp377Sm501Ac97::ResetCodec(bool cold) {
    emu_.Get<Cs4297aCodec>().Reset();
    codec_ready_ = cold ? false : codec_ready_;
    if (cold) codec_ready_frames_ = 0u;
    codec_read_pending_ = false;
    rx_slot1_ = 0u;
    rx_slot2_ = 0u;
    rx_slot3_ = 0u;
    rx_slot4_ = 0u;
}

void SiemensMp377Sm501Ac97::NoteTxSlotWrite(uint32_t dirty_bit) {
    tx_dirty_mask_ |= dirty_bit;
}

void SiemensMp377Sm501Ac97::AdvanceMachineCycles(uint32_t cycles, uint8_t mode) {
    std::lock_guard<std::recursive_mutex> lock(state_mutex_);
    /* SM501 MMCC Databook v1.02, AC Link functional overview, Mode Select,
       Table 18-15; siemens_mp377_v1040 SM501 firmware CODE:08AF..0A80. */
    constexpr uint32_t kHifPeriodsPerFrame = 2000u;
    const uint32_t cclk_divisor = 2u + (mode & 3u);
    frame_phase_ += cycles * cclk_divisor;
    while (frame_phase_ >= kHifPeriodsPerFrame) {
        frame_phase_ -= kHifPeriodsPerFrame;
        ProcessFrame();
    }
}

void SiemensMp377Sm501Ac97::ClockFrame() {
    std::lock_guard<std::recursive_mutex> lock(state_mutex_);
    ProcessFrame();
}

void SiemensMp377Sm501Ac97::ProcessFrame() {
    UpdateStatus();

    if (!bclk_running_) {
        tx_dirty_mask_ &= kDirtyTag;
        return;
    }

    /* CS4297A AC characteristics, Tsync2crd: Codec Ready is asserted within
       62.5 us of the first active SYNC, i.e. within three 48-kHz frames. */
    if (!codec_ready_) {
        if (codec_ready_frames_ < 3u) ++codec_ready_frames_;
        if (codec_ready_frames_ == 3u) codec_ready_ = true;
        UpdateStatus();
    }

    if (irq_pending_ && drop_count_ < 0x3Fu) ++drop_count_;

    uint32_t rx_tag = codec_ready_ ? kTagValidFrame : 0u;
    if (codec_ready_ && AdcReady()) rx_tag |= kTagSlot3Valid | kTagSlot4Valid;
    if (codec_ready_ && codec_read_pending_) {
        rx_slot1_ = static_cast<uint32_t>(codec_read_register_ & 0x7Eu) << 12u;
        rx_slot2_ = static_cast<uint32_t>(codec_read_data_) << 4u;
        rx_tag |= kTagSlot1Valid | kTagSlot2Valid;
        codec_read_pending_ = false;
    } else {
        rx_slot1_ = 0u;
        rx_slot2_ = 0u;
    }

    if ((tx_slot0_ & kTagValidFrame) == 0u) {
        rx_slot0_ = rx_tag;
        tx_dirty_mask_ &= kDirtyTag;
        Registers().regs_[kRxSlot0TagReg / 4u] = rx_slot0_;
        Registers().regs_[kRxSlot1StatusAddrReg / 4u] = rx_slot1_;
        Registers().regs_[kRxSlot2StatusDataReg / 4u] = rx_slot2_;
        RaiseInterrupt();
        return;
    }

    const bool want_cmd = (tx_slot0_ & (kTagSlot1Valid | kTagSlot2Valid)) == (kTagSlot1Valid | kTagSlot2Valid);
    const bool want_pcm = (tx_slot0_ & (kTagSlot3Valid | kTagSlot4Valid)) == (kTagSlot3Valid | kTagSlot4Valid);

    uint32_t handled_dirty = 0u;

    if (codec_ready_ && want_cmd) {
        const uint32_t reg = (tx_slot1_ >> 12) & 0x7Eu;
        const bool is_read = (tx_slot1_ & kCmdReadBit) != 0u;
        if (is_read) {
            /* AC'97 read-back address/data appear in the input frame after
               the frame containing the request (CS4297A section 3.2). */
            codec_read_register_ = static_cast<uint8_t>(reg);
            codec_read_data_ = emu_.Get<Cs4297aCodec>().ReadRegister(reg, codec_ready_);
            codec_read_pending_ = true;
        } else {
            const uint16_t data = static_cast<uint16_t>((tx_slot2_ >> 4) & 0xFFFFu);
            emu_.Get<Cs4297aCodec>().WriteRegister(reg, data);
            if (reg == 0x26u) {
                if (!LinkPowered()) {
                    codec_ready_ = false;
                    bclk_running_ = false;
                }
                if (!DacReady()) emu_.Get<SiemensMp377Sm501AudioOutput>().HandleDacPowerDown();
                UpdateStatus();
            }
        }
        handled_dirty |= kDirtySlot1 | kDirtySlot2;
    }

    if (codec_ready_ && want_pcm && DacReady()) {
        emu_.Get<SiemensMp377Sm501AudioOutput>().QueueAc97PcmSample(tx_slot3_, tx_slot4_);
        handled_dirty |= kDirtySlot3 | kDirtySlot4;
    }

    rx_slot0_ = rx_tag;
    auto& registers = Registers();
    registers.regs_[kRxSlot0TagReg / 4u] = rx_slot0_;
    registers.regs_[kRxSlot1StatusAddrReg / 4u] = rx_slot1_;
    registers.regs_[kRxSlot2StatusDataReg / 4u] = rx_slot2_;
    registers.regs_[kRxSlot3PcmLeftReg / 4u] = rx_slot3_;
    registers.regs_[kRxSlot4PcmRightReg / 4u] = rx_slot4_;
    tx_dirty_mask_ &= ~handled_dirty;
    tx_dirty_mask_ &= ~kDirtyTag;
    RaiseInterrupt();
}
void SiemensMp377Sm501Ac97::RaiseInterrupt() {
    irq_pending_ = true;
    emu_.Get<SiemensMp377Sm501AudioMcu>().SignalAc97Interrupt();
    Registers().RaiseSm501InterruptBits(kSm501Ac97IrqBit);
}

void SiemensMp377Sm501Ac97::ClearInterrupt() {
    std::lock_guard<std::recursive_mutex> lock(state_mutex_);
    auto& registers = Registers();
    if (!irq_pending_ && (registers.Sm501LatchedInterruptStatus() & kSm501Ac97IrqBit) == 0u) return;
    irq_pending_ = false;
    registers.ClearSm501InterruptBits(kSm501Ac97IrqBit);
}

SiemensMp377Sm501Regs& SiemensMp377Sm501Ac97::Registers() const {
    return emu_.Get<SiemensMp377Sm501Regs>();
}

bool SiemensMp377Sm501Ac97::DacReady() const {
    std::lock_guard<std::recursive_mutex> lock(state_mutex_);
    return emu_.Get<Cs4297aCodec>().DacReady(codec_ready_);
}

bool SiemensMp377Sm501Ac97::AdcReady() const {
    std::lock_guard<std::recursive_mutex> lock(state_mutex_);
    return emu_.Get<Cs4297aCodec>().AdcReady(codec_ready_);
}

bool SiemensMp377Sm501Ac97::LinkPowered() const {
    return emu_.Get<Cs4297aCodec>().LinkPowered();
}

void SiemensMp377Sm501Ac97::SaveCodecState(StateWriter& writer) const {
    emu_.Get<Cs4297aCodec>().SaveState(writer);
}

void SiemensMp377Sm501Ac97::RestoreCodecState(StateReader& reader) {
    emu_.Get<Cs4297aCodec>().RestoreState(reader);
}

REGISTER_SERVICE(SiemensMp377Sm501Ac97);

} // namespace siemens_mp377
