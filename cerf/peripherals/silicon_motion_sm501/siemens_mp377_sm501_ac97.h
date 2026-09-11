#pragma once

#include "../../core/service.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <mutex>

namespace siemens_mp377 {

class SiemensMp377Sm501Regs;
class SiemensMp377Sm501Ac97;

inline constexpr uint32_t kSm501Ac97IrqBit = 1u << 17;

/* SM501 MSOC Databook, Chapter 11: AC97-link controller registers and slots.
   Cirrus CS4297A datasheet, Section 4 and Table 1: codec register semantics,
   reset defaults, power status and vendor identification. */
class SiemensMp377Sm501Ac97 : public Service {
public:
    using Service::Service;

    static constexpr uint32_t kBase = 0x0A0100u;

    bool ShouldRegister() override;
    void OnReady() override;

    static bool IsRegister(uint32_t offset);
    uint32_t Read(uint32_t offset, bool clear_irq);
    void Write(uint32_t offset, uint32_t old_value, uint32_t value);
    uint8_t ReadByte(uint32_t offset, bool clear_irq);
    void WriteByte(uint32_t offset, uint8_t value);
    void AdvanceMachineCycles(uint32_t cycles, uint8_t mode);
    void ClockFrame();
    void UpdateStatus();
    void ClearInterrupt();
    bool DacReady() const;
    bool AdcReady() const;
    std::unique_lock<std::recursive_mutex> LockForState() const {
        return std::unique_lock<std::recursive_mutex>(state_mutex_);
    }
    void SaveState(StateWriter& writer) const {
        std::lock_guard<std::recursive_mutex> lock(state_mutex_);
        SaveCodecState(writer);
        writer.Write(control_);
        writer.Write(tx_slot0_);
        writer.Write(tx_slot1_);
        writer.Write(tx_slot2_);
        writer.Write(tx_slot3_);
        writer.Write(tx_slot4_);
        writer.Write(rx_slot0_);
        writer.Write(rx_slot1_);
        writer.Write(rx_slot2_);
        writer.Write(rx_slot3_);
        writer.Write(rx_slot4_);
        writer.Write(drop_count_);
        writer.Write(irq_pending_);
        writer.Write(codec_ready_);
        writer.Write(bclk_running_);
        writer.Write(tx_dirty_mask_);
        writer.Write(frame_phase_);
        writer.Write(codec_ready_frames_);
        writer.Write(codec_read_pending_);
        writer.Write(codec_read_register_);
        writer.Write(codec_read_data_);
    }
    void RestoreState(StateReader& reader) {
        std::lock_guard<std::recursive_mutex> lock(state_mutex_);
        RestoreCodecState(reader);
        reader.Read(control_);
        reader.Read(tx_slot0_);
        reader.Read(tx_slot1_);
        reader.Read(tx_slot2_);
        reader.Read(tx_slot3_);
        reader.Read(tx_slot4_);
        reader.Read(rx_slot0_);
        reader.Read(rx_slot1_);
        reader.Read(rx_slot2_);
        reader.Read(rx_slot3_);
        reader.Read(rx_slot4_);
        reader.Read(drop_count_);
        reader.Read(irq_pending_);
        reader.Read(codec_ready_);
        reader.Read(bclk_running_);
        reader.Read(tx_dirty_mask_);
        reader.Read(frame_phase_);
        reader.Read(codec_ready_frames_);
        reader.Read(codec_read_pending_);
        reader.Read(codec_read_register_);
        reader.Read(codec_read_data_);
    }

private:
    static constexpr uint32_t kTxSlot0TagReg = 0x0A0100u;
    static constexpr uint32_t kTxSlot1CmdAddrReg = 0x0A0104u;
    static constexpr uint32_t kTxSlot2CmdDataReg = 0x0A0108u;
    static constexpr uint32_t kTxSlot3PcmLeftReg = 0x0A010Cu;
    static constexpr uint32_t kTxSlot4PcmRightReg = 0x0A0110u;
    static constexpr uint32_t kRxSlot0TagReg = 0x0A0140u;
    static constexpr uint32_t kRxSlot1StatusAddrReg = 0x0A0144u;
    static constexpr uint32_t kRxSlot2StatusDataReg = 0x0A0148u;
    static constexpr uint32_t kRxSlot3PcmLeftReg = 0x0A014Cu;
    static constexpr uint32_t kRxSlot4PcmRightReg = 0x0A0150u;
    static constexpr uint32_t kControlStatusReg = 0x0A0180u;

    static constexpr uint32_t kTagValidFrame = 1u << 15;
    static constexpr uint32_t kTagSlot1Valid = 1u << 14;
    static constexpr uint32_t kTagSlot2Valid = 1u << 13;
    static constexpr uint32_t kTagSlot3Valid = 1u << 12;
    static constexpr uint32_t kTagSlot4Valid = 1u << 11;
    static constexpr uint32_t kDirtyTag = 1u << 0;
    static constexpr uint32_t kDirtySlot1 = 1u << 1;
    static constexpr uint32_t kDirtySlot2 = 1u << 2;
    static constexpr uint32_t kDirtySlot3 = 1u << 3;
    static constexpr uint32_t kDirtySlot4 = 1u << 4;
    static constexpr uint32_t kCmdReadBit = 1u << 19;
    static constexpr uint32_t kCmdIndexMask = 0x0007F000u;
    static constexpr uint32_t kSlotDataMask = 0x000FFFFFu;
    static constexpr uint32_t kCmdDataMask = 0x000FFFF0u;
    static constexpr uint32_t kCtrlEnable = 1u << 0;
    static constexpr uint32_t kCtrlColdReset = 1u << 1;
    static constexpr uint32_t kCtrlWarmReset = 1u << 2;
    static constexpr uint32_t kCtrlWakeIrqEnable = 1u << 3;
    static constexpr uint32_t kCtrlStatusShift = 4u;
    static constexpr uint32_t kCtrlBclkRunning = 1u << 8;
    static constexpr uint32_t kCtrlStopSync = 1u << 9;

    static bool IsTxRegister(uint32_t offset);
    static bool IsRxRegister(uint32_t offset);
    void ResetController();
    uint32_t ControlStatusValue() const;
    void ResetCodec(bool cold);
    void NoteTxSlotWrite(uint32_t dirty_bit);
    void ProcessFrame();
    void RaiseInterrupt();
    bool LinkPowered() const;
    void SaveCodecState(StateWriter& writer) const;
    void RestoreCodecState(StateReader& reader);
    SiemensMp377Sm501Regs& Registers() const;
    uint32_t control_ = 0;
    uint32_t tx_slot0_ = 0;
    uint32_t tx_slot1_ = 0;
    uint32_t tx_slot2_ = 0;
    uint32_t tx_slot3_ = 0;
    uint32_t tx_slot4_ = 0;
    uint32_t rx_slot0_ = 0;
    uint32_t rx_slot1_ = 0;
    uint32_t rx_slot2_ = 0;
    uint32_t rx_slot3_ = 0;
    uint32_t rx_slot4_ = 0;
    uint32_t drop_count_ = 0;
    bool irq_pending_ = false;
    bool codec_ready_ = false;
    bool bclk_running_ = false;
    uint32_t tx_dirty_mask_ = 0;
    uint32_t frame_phase_ = 0;
    uint8_t codec_ready_frames_ = 0;
    bool codec_read_pending_ = false;
    uint8_t codec_read_register_ = 0;
    uint16_t codec_read_data_ = 0;
    mutable std::recursive_mutex state_mutex_;
};

} // namespace siemens_mp377
