#include "../../peripherals/peripheral_base.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../board_context.h"
#include "devemu_id.h"

#include <array>
#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x500F0000u;
constexpr uint32_t kSpan = 0x2120u;

/* devemu_wm2003se dmatrans.dll sub_19111BC 0x19111BC maps the window from
   0xB10F0000 over 0x2120 bytes and publishes each channel's flag dword as
   that base + 0x2000 + 4n. */
constexpr uint32_t kMappedWindowBase = 0xB10F0000u;

constexpr uint32_t kSharedSize = 0x2080u;

constexpr uint32_t kHostStatusBase = 0x2000u;
constexpr uint32_t kHostStatusTop  = 0x2010u;

constexpr uint32_t kChannelCount   = 4u;
constexpr uint32_t kChannelStride  = 0x20u;
constexpr uint32_t kChannelBase    = 0x2080u;
constexpr uint32_t kChannelTop     = kChannelBase + kChannelCount * kChannelStride;
constexpr uint32_t kChannelControl = 0x00u;
constexpr uint32_t kChannelConfig  = 0x04u;
constexpr uint32_t kChannelIrq     = 0x10u;

constexpr uint32_t kChannelPresent = 0x001u;
constexpr uint32_t kChannelEnable  = 0x100u;
constexpr uint32_t kChannelProbe   = 0x001u;

/* devemu_wm2003se dmatrans.dll DMA_Write 0x191187C rings +0x0C with the
   descriptor at +0x201C, whose third word is the status it then reads. */
constexpr uint32_t kChannelTxDoorbell = 0x0Cu;

constexpr uint32_t kTxDescriptor     = 0x201Cu;
constexpr uint32_t kDescriptorStatus = 0x8u;

constexpr uint32_t kTransferNoService = 1u;

constexpr uint32_t kCmdSelect    = 0x2100u;
constexpr uint32_t kCmdOperation = 0x2104u;
constexpr uint32_t kCmdStatus    = 0x2108u;

/* devemu_wm2003se dmatrans.dll DMA_Open 0x1911654 selects at +0x2100, writes
   operation 1 at +0x2104 and treats a zero at +0x2108 as an opened channel;
   for index 8 and 9 it writes operation 8 or 16 and takes +0x2108 as a handle
   it requires to be >= 0x80000000. DMA_Close 0x19117B8 writes operation 2. */
constexpr uint32_t kOpOpen        = 1u;
constexpr uint32_t kOpClose       = 2u;
constexpr uint32_t kOpAllocFirst  = 8u;
constexpr uint32_t kOpAllocSecond = 16u;

constexpr uint32_t kChannelOpened   = 0u;
constexpr uint32_t kNoDynamicHandle = 0u;

class DevEmuDmaTransport : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Devemu;
    }

    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSpan; }

    uint8_t ReadByte(uint32_t addr) override {
        RequireGuestOwned("ReadByte", addr, sizeof(uint8_t), 0);
        return shared_[addr - kBase];
    }
    uint16_t ReadHalf(uint32_t addr) override {
        RequireGuestOwned("ReadHalf", addr, sizeof(uint16_t), 0);
        return cerf::le::U16(shared_.data(), addr - kBase);
    }
    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        if (off < kSharedSize) {
            RequireGuestOwned("ReadWord", addr, sizeof(uint32_t), 0);
            return cerf::le::U32(shared_.data(), off);
        }
        if (off >= kChannelBase && off < kChannelTop) {
            const uint32_t n   = (off - kChannelBase) / kChannelStride;
            const uint32_t reg = (off - kChannelBase) % kChannelStride;
            if (reg == kChannelControl)
                return ch_control_[n] | kChannelPresent;
        }
        if (off == kCmdStatus) {
            if (cmd_operation_ == kOpOpen && ChannelEnabled(cmd_select_))
                return kChannelOpened;
            if (cmd_operation_ == kOpAllocFirst ||
                cmd_operation_ == kOpAllocSecond)
                return kNoDynamicHandle;
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteByte(uint32_t addr, uint8_t value) override {
        RequireGuestOwned("WriteByte", addr, sizeof(value), value);
        shared_[addr - kBase] = value;
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        RequireGuestOwned("WriteHalf", addr, sizeof(value), value);
        cerf::le::Put16(shared_.data() + (addr - kBase), value);
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;
        if (off < kSharedSize) {
            RequireGuestOwned("WriteWord", addr, sizeof(value), value);
            cerf::le::Put32(shared_.data() + off, value);
            return;
        }
        if (off >= kChannelBase && off < kChannelTop) {
            const uint32_t n   = (off - kChannelBase) / kChannelStride;
            const uint32_t reg = (off - kChannelBase) % kChannelStride;
            if (reg == kChannelControl &&
                (value == kChannelProbe ||
                 value == (kChannelPresent | kChannelEnable))) {
                ch_control_[n] = value & kChannelEnable;
                return;
            }
            if (reg == kChannelConfig &&
                IsWindowAddress(value, kHostStatusBase + 4u * n))
                return;
            /* devemu_wm2003se dmatrans.dll DMA_Init 0x1911540 writes 0x1E at
               32 * v4 + 8336, which is +0x10 of the channel block. */
            if (reg == kChannelIrq)
                return;
            if (reg == kChannelTxDoorbell && ChannelEnabled(n) &&
                IsWindowAddress(value, kTxDescriptor)) {
                CompleteWithoutService(kTxDescriptor);
                return;
            }
        }
        if (off == kCmdSelect && value < kChannelCount) {
            cmd_select_ = value;
            return;
        }
        if (off == kCmdOperation) {
            if (value == kOpOpen || value == kOpClose ||
                value == kOpAllocFirst || value == kOpAllocSecond) {
                cmd_operation_ = value;
                return;
            }
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    void SaveState(StateWriter& w) override {
        w.WriteBytes("shared", shared_.data(), shared_.size());
        for (uint32_t v : ch_control_) w.Write<uint32_t>("ch_control", v);
        w.Write<uint32_t>("cmd_select", cmd_select_);
        w.Write<uint32_t>("cmd_operation", cmd_operation_);
    }
    void RestoreState(StateReader& r) override {
        r.ReadBytes("shared", shared_.data(), shared_.size());
        for (uint32_t& v : ch_control_) r.Read("ch_control", v);
        r.Read("cmd_select", cmd_select_);
        r.Read("cmd_operation", cmd_operation_);
    }

private:
    /* devemu_wm2003se dmatrans.dll DMA_Init 0x1911540 rejects a channel whose
       control bit 0 reads back clear, then writes the control value with bit 8
       set before DMA_Open 0x1911654 selects that channel. */
    bool ChannelEnabled(uint32_t n) const {
        return (ch_control_[n] & kChannelEnable) != 0u;
    }

    bool IsWindowAddress(uint32_t value, uint32_t off) const {
        return value == kBase + off || value == kMappedWindowBase + off;
    }

    void CompleteWithoutService(uint32_t descriptor) {
        cerf::le::Put32(shared_.data() + descriptor + kDescriptorStatus, kTransferNoService);
    }

    void RequireGuestOwned(const char* op, uint32_t addr,
                           uint32_t size, uint64_t value) const {
        const uint32_t off = addr - kBase;
        if (off + size > kSharedSize)
            HaltUnsupportedAccess(op, addr, value);
        if (off < kHostStatusTop && off + size > kHostStatusBase)
            HaltUnsupportedAccess(op, addr, value);
    }

    std::array<uint8_t, kSharedSize> shared_{};
    std::array<uint32_t, kChannelCount> ch_control_{};
    uint32_t cmd_select_    = 0;
    uint32_t cmd_operation_ = 0;
};

}  /* namespace */

REGISTER_SERVICE(DevEmuDmaTransport);
