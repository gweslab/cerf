#pragma once

#include "../../peripherals/peripheral_base.h"

#include "msm8255_clock_reset.h"
#include "msm8255_crci_bus.h"
#include "msm8255_sdcc_regs.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../irq_controller.h"
#include "../../peripherals/mmc/mmc_card.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <atomic>
#include <cstdint>
#include <vector>

namespace cerf_msm8255_sdcc_detail {

template <uint32_t kBase, uint32_t kSize, uint32_t kResetClock,
          uint32_t kSlotIndex, uint32_t kIrqSource0, uint32_t kIrqSource1,
          uint32_t kCrci>
class Msm8255SdccWindowBase : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Msm8255;
    }

    void OnReady() override {
        emu_.Get<GuestCpuReset>().RegisterResetListener(
            [this](ResetLineKind) { ResetState(); });
        emu_.Get<Msm8255ClockReset>().RegisterListener(kResetClock, [this] {
            RequireNoTransferInFlight("a clkregim clock reset");
            ResetState();
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<Msm8255CrciBus>().DeclareFifo(kCrci, kBase + kFifo,
                                              kFifoBytes);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        if (off >= kFifo && off < kFifo + kFifoBytes) return ReadFifo();
        switch (off) {
        case kPower:     return Load(power_);
        case kClock:     return Load(clock_);
        case kMask0:     return Load(mask0_);
        case kMask1:     return Load(mask1_);
        case kStatus:    return Load(status_);
        case kResponse0: return Load(response_[0]);
        case kResponse1: return Load(response_[1]);
        case kResponse2: return Load(response_[2]);
        case kResponse3: return Load(response_[3]);
        default:         break;
        }
        HaltUnsupportedAccess("ReadWord", addr, 0u);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        switch (addr - kBase) {
        case kPower:
            if ((value & ~kPowerWritable) == 0u) {
                Store(power_, value);
                return;
            }
            break;
        case kClock:
            if ((value & ~kClockWritable) == 0u) {
                Store(clock_, value);
                return;
            }
            break;
        case kMask0:
            if ((value & ~kMaskWritable) == 0u) {
                Store(mask0_, value);
                UpdateIrq();
                return;
            }
            break;
        case kMask1:
            if ((value & ~kMaskWritable) == 0u) {
                Store(mask1_, value);
                UpdateIrq();
                return;
            }
            break;
        case kArgument:
            Store(argument_, value);
            return;
        case kCommand:
            if (value == kQuiescent) {
                return;
            }
            if ((value & kCmdEnable) != 0u && (value & ~kCmdModelled) == 0u) {
                IssueCommand(value);
                return;
            }
            break;
        case kDataTimer:
            Store(data_timer_, value);
            return;
        case kDataLength:
            Store(data_length_, value);
            return;
        case kDataCtrl:
            if ((value & ~kDataCtrlModelled) == 0u) {
                StartDataPhase(value);
                return;
            }
            break;
        case kClear:
            if ((value & ~kClearStaticMask) == 0u) {
                Store(status_, Load(status_) & ~value);
                UpdateIrq();
                return;
            }
            break;
        default:
            break;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    void SaveState(StateWriter& w) override {
        w.Write<uint32_t>(Load(power_));
        w.Write<uint32_t>(Load(clock_));
        w.Write<uint32_t>(Load(mask0_));
        w.Write<uint32_t>(Load(mask1_));
        w.Write<uint32_t>(Load(argument_));
        w.Write<uint32_t>(Load(status_));
        for (auto& word : response_) w.Write<uint32_t>(Load(word));
        w.Write<uint32_t>(Load(data_timer_));
        w.Write<uint32_t>(Load(data_length_));
        w.Write<uint32_t>(Load(data_ctrl_));
        w.Write<uint32_t>(read_pos_);
        w.Write<uint32_t>(static_cast<uint32_t>(read_data_.size()));
        for (uint8_t b : read_data_) w.Write<uint8_t>(b);
        w.Write<uint32_t>(data_count_);
        if (auto* card = CardForSlot()) card->SaveState(w);
    }

    void RestoreState(StateReader& r) override {
        RestoreField(r, power_, kPowerWritable, kPower);
        RestoreField(r, clock_, kClockWritable, kClock);
        RestoreField(r, mask0_, kMaskWritable, kMask0);
        RestoreField(r, mask1_, kMaskWritable, kMask1);
        RestoreField(r, argument_, 0xFFFFFFFFu, kArgument);
        RestoreField(r, status_, kStatusLatchable, kStatus);
        for (uint32_t i = 0; i < 4u; ++i) {
            RestoreField(r, response_[i], 0xFFFFFFFFu, kResponse0 + i * 4u);
        }
        RestoreField(r, data_timer_, 0xFFFFFFFFu, kDataTimer);
        RestoreField(r, data_length_, 0xFFFFFFFFu, kDataLength);
        RestoreField(r, data_ctrl_, kDataCtrlModelled, kDataCtrl);
        uint32_t pos    = 0u;
        uint32_t staged = 0u;
        uint32_t count  = 0u;
        r.Read(pos);
        r.Read(staged);
        read_data_.resize(staged);
        for (uint32_t i = 0; i < staged; ++i) r.Read(read_data_[i]);
        r.Read(count);
        RequireReachableDataPath(pos, staged, count);
        read_pos_   = pos;
        data_count_ = count;
        if (auto* card = CardForSlot()) card->RestoreState(r);
    }

    void PostRestore() override {
        if (auto* card = CardForSlot()) card->PostRestore();
        DriveCrci();
        UpdateIrq();
    }

private:
    static uint32_t Load(const std::atomic<uint32_t>& reg) {
        return reg.load(std::memory_order_acquire);
    }

    static void Store(std::atomic<uint32_t>& reg, uint32_t value) {
        reg.store(value, std::memory_order_release);
    }

    MmcCard* CardForSlot() {
        auto* card = emu_.TryGet<MmcCard>();
        return (card != nullptr && card->SlotIndex() == kSlotIndex) ? card
                                                                    : nullptr;
    }

    void LatchStatus(uint32_t event) {
        Store(status_, Load(status_) | event);
        UpdateIrq();
    }

    void UpdateIrq() {
        const uint32_t status = Load(status_);
        auto& vic = emu_.Get<IrqController>();
        DriveLine(vic, kIrqSource0, (status & Load(mask0_)) != 0u);
        DriveLine(vic, kIrqSource1, (status & Load(mask1_)) != 0u);
    }

    static void DriveLine(IrqController& vic, uint32_t source, bool high) {
        if (high) {
            vic.AssertIrq(source);
        } else {
            vic.DeAssertIrq(source);
        }
    }

    void IssueCommand(uint32_t value) {
        const bool wants_response = (value & kCmdResponse) != 0u;
        const bool wants_long     = (value & kCmdLongRsp) != 0u;
        const bool wants_progena  = (value & kCmdProgEna) != 0u;
        const uint32_t done = wants_progena
                                  ? (kStatusCmdRespEnd | kStatusProgDone)
                                  : kStatusCmdRespEnd;

        MmcCard* card = CardForSlot();
        if (card == nullptr) {
            if (wants_progena) HaltProgEnaWithoutResponse(value);
            LatchStatus(wants_response ? kStatusCmdTimeout : kStatusCmdSent);
            return;
        }

        uint32_t resp[4] = {0u, 0u, 0u, 0u};
        const MmcCommandResult result = card->Command(
            static_cast<uint8_t>(value & kCmdIndex), Load(argument_), resp);

        switch (result) {
        case MmcCommandResult::NoResponse:
            if (wants_progena) HaltProgEnaWithoutResponse(value);
            LatchStatus(wants_response ? kStatusCmdTimeout : kStatusCmdSent);
            return;
        case MmcCommandResult::Short:
            if (wants_response && !wants_long) {
                Store(response_[0], resp[0]);
                LatchStatus(done);
                BindDataPhase(*card);
                return;
            }
            break;
        case MmcCommandResult::Long:
            if (wants_response && wants_long) {
                for (uint32_t i = 0; i < 4u; ++i) Store(response_[i], resp[i]);
                LatchStatus(done);
                BindDataPhase(*card);
                return;
            }
            break;
        }

        emu_.Get<Fatal>().Die(
            "Peripheral at 0x%08X: CMD%u answered with response class %u while "
            "the command word 0x%08X asked for a different one",
            kBase, static_cast<unsigned>(value & kCmdIndex),
            static_cast<unsigned>(result), value);
    }

    uint32_t BlockBytes(uint32_t ctrl) const {
        return (ctrl & kDataCtrlBlockSize) >> kDataCtrlBlockSizeShift;
    }

    void RequireNoTransferInFlight(const char* cause) {
        if (read_pos_ < read_data_.size()) {
            emu_.Get<Fatal>().Die(
                "Peripheral at 0x%08X: %s ends a transfer with %u of %u bytes "
                "undrained, and ending a transfer early is not modeled",
                kBase, cause, read_pos_,
                static_cast<unsigned>(read_data_.size()));
        }
    }

    void StartDataPhase(uint32_t value) {
        RequireNoTransferInFlight("a data control write");
        Store(data_ctrl_, value);
        read_data_.clear();
        read_pos_ = 0u;
        if ((value & kDataCtrlEnable) == 0u) {
            DriveCrci();
            return;
        }
        if ((value & kDataCtrlDirection) == 0u) {
            emu_.Get<Fatal>().Die(
                "Peripheral at 0x%08X: data control 0x%08X starts a "
                "host-to-card data phase, which is not modeled", kBase, value);
        }
        if ((value & kDataCtrlDmaEnable) == 0u) {
            emu_.Get<Fatal>().Die(
                "Peripheral at 0x%08X: data control 0x%08X starts a "
                "card-to-host data phase without DMA, and the receive FIFO "
                "status bits are not modeled", kBase, value);
        }
        if (CardForSlot() == nullptr) {
            emu_.Get<Fatal>().Die(
                "Peripheral at 0x%08X: data control 0x%08X starts a data phase "
                "with no card in the slot", kBase, value);
        }
        const uint32_t block  = BlockBytes(value);
        const uint32_t length = Load(data_length_);
        if (length > kDataLengthMax) {
            emu_.Get<Fatal>().Die(
                "Peripheral at 0x%08X: data length 0x%08X sets bits past the "
                "%u-bit length field", kBase, length, kDataLengthBits);
        }
        if (block == 0u || length == 0u || length % block != 0u) {
            emu_.Get<Fatal>().Die(
                "Peripheral at 0x%08X: data control 0x%08X carries a %u byte "
                "block over a %u byte transfer that is not a whole number of "
                "blocks, which is not modeled", kBase, value, block, length);
        }
        data_count_ = length;
        DriveCrci();
    }

    void BindDataPhase(MmcCard& card) {
        const std::vector<uint8_t>& staged = card.ReadData();
        const uint32_t ctrl  = Load(data_ctrl_);
        const bool     armed = (ctrl & kDataCtrlEnable) != 0u;
        if (staged.empty()) {
            if (armed && read_data_.empty()) {
                emu_.Get<Fatal>().Die(
                    "Peripheral at 0x%08X: data control 0x%08X arms a data "
                    "phase the card answered with no data, and a data "
                    "timeout is not modeled", kBase, ctrl);
            }
            return;
        }
        if (!armed || data_count_ == 0u || read_pos_ < read_data_.size()) {
            emu_.Get<Fatal>().Die(
                "Peripheral at 0x%08X: the card answered with %u bytes while "
                "data control 0x%08X has %u bytes left to receive and %u "
                "bytes undrained", kBase, static_cast<unsigned>(staged.size()),
                ctrl, data_count_,
                static_cast<unsigned>(read_data_.size() - read_pos_));
        }
        if (staged.size() != BlockBytes(ctrl)) {
            emu_.Get<Fatal>().Die(
                "Peripheral at 0x%08X: data control carries %u byte blocks and "
                "the card answered with a %u byte block", kBase,
                BlockBytes(ctrl), static_cast<unsigned>(staged.size()));
        }
        read_data_ = staged;
        read_pos_  = 0u;
        DriveCrci();
    }

    void DriveCrci() {
        auto& lines = emu_.Get<Msm8255CrciBus>();
        if (read_pos_ < read_data_.size()) {
            lines.Assert(kCrci);
        } else {
            lines.Deassert(kCrci);
        }
    }

    uint32_t ReadFifo() {
        if (read_pos_ + 4u > read_data_.size()) {
            emu_.Get<Fatal>().Die(
                "Peripheral at 0x%08X: fifo read at byte %u passes the %u bytes "
                "of the data phase in progress",
                kBase, read_pos_, static_cast<unsigned>(read_data_.size()));
        }
        uint32_t v = 0u;
        for (uint32_t i = 0; i < 4u; ++i) {
            v |= static_cast<uint32_t>(read_data_[read_pos_ + i]) << (8u * i);
        }
        read_pos_ += 4u;
        if (read_pos_ != read_data_.size()) return v;

        MmcCard* card = CardForSlot();
        data_count_ -= read_pos_;
        if (data_count_ != 0u) {
            card->NextBlock();
            const std::vector<uint8_t>& next = card->ReadData();
            if (next.size() != read_data_.size()) {
                emu_.Get<Fatal>().Die(
                    "Peripheral at 0x%08X: the card answered the next block "
                    "with %u bytes where the transfer carries %u byte blocks",
                    kBase, static_cast<unsigned>(next.size()),
                    static_cast<unsigned>(read_data_.size()));
            }
            read_data_ = next;
            read_pos_  = 0u;
            LatchStatus(kStatusDataBlockEnd);
            return v;
        }
        card->EndDataPhase();
        DriveCrci();
        LatchStatus(kStatusDataBlockEnd | kStatusDataEnd);
        return v;
    }

    void RequireReachableDataPath(uint32_t pos, uint32_t staged,
                                  uint32_t count) {
        const uint32_t ctrl      = Load(data_ctrl_);
        const uint32_t block     = BlockBytes(ctrl);
        const bool     armed     = (ctrl & kDataCtrlEnable) != 0u;
        const bool     receiving = armed &&
                                   (ctrl & kDataCtrlDirection) != 0u &&
                                   (ctrl & kDataCtrlDmaEnable) != 0u &&
                                   CardForSlot() != nullptr;
        const bool     reachable =
            count <= kDataLengthMax &&
            (staged == 0u
                 ? (pos == 0u &&
                    (!armed ||
                     (receiving && block != 0u && count != 0u &&
                      count % block == 0u)))
                 : (receiving && (pos & 3u) == 0u && pos <= staged &&
                    staged == block && count % block == 0u &&
                    (pos < staged ? count >= block : count == 0u)));
        if (!reachable) {
            emu_.Get<Fatal>().Die(
                "Peripheral at 0x%08X: restored fifo cursor %u over %u staged "
                "bytes with %u bytes left to receive under data control "
                "0x%08X is not a state this data path reaches",
                kBase, pos, staged, count, ctrl);
        }
    }

    [[noreturn]] void HaltProgEnaWithoutResponse(uint32_t value) {
        emu_.Get<Fatal>().Die(
            "Peripheral at 0x%08X: CMD%u asks for programming-done but no card "
            "answers it (command word 0x%08X)",
            kBase, static_cast<unsigned>(value & kCmdIndex), value);
    }

    void ResetState() {
        Store(power_, kUngroundedPowerOn);
        Store(clock_, kUngroundedPowerOn);
        Store(mask0_, kUngroundedPowerOn);
        Store(mask1_, kUngroundedPowerOn);
        Store(argument_, kUngroundedPowerOn);
        Store(status_, 0u);
        for (auto& word : response_) Store(word, 0u);
        Store(data_timer_, kUngroundedPowerOn);
        Store(data_length_, kUngroundedPowerOn);
        Store(data_ctrl_, kUngroundedPowerOn);
        read_data_.clear();
        read_pos_   = 0u;
        data_count_ = kUngroundedPowerOn;
        DriveCrci();
        UpdateIrq();
    }

    void RestoreField(StateReader& r, std::atomic<uint32_t>& reg,
                      uint32_t writable, uint32_t offset) {
        uint32_t value = kUngroundedPowerOn;
        r.Read(value);
        if ((value & ~writable) != 0u) {
            emu_.Get<Fatal>().Die(
                "Peripheral at 0x%08X: restored +0x%03X value 0x%08X carries "
                "bits the guest never writes", kBase, offset, value);
        }
        Store(reg, value);
    }

    std::atomic<uint32_t> power_{kUngroundedPowerOn};
    std::atomic<uint32_t> clock_{kUngroundedPowerOn};
    std::atomic<uint32_t> mask0_{kUngroundedPowerOn};
    std::atomic<uint32_t> mask1_{kUngroundedPowerOn};
    std::atomic<uint32_t> argument_{kUngroundedPowerOn};
    std::atomic<uint32_t> status_{0};
    std::atomic<uint32_t> response_[4]{};
    std::atomic<uint32_t> data_timer_{kUngroundedPowerOn};
    std::atomic<uint32_t> data_length_{kUngroundedPowerOn};
    std::atomic<uint32_t> data_ctrl_{kUngroundedPowerOn};
    std::vector<uint8_t>  read_data_;
    uint32_t              read_pos_   = 0u;
    uint32_t              data_count_ = kUngroundedPowerOn;
};

}  // namespace cerf_msm8255_sdcc_detail
