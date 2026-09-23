#include "../../peripherals/peripheral_base.h"

#include "msm8255_mddi_client.h"
#include "msm8255_mddi_link_list.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/emulated_memory.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../irq_controller.h"
#include "../guest_cpu_reset.h"

#include <atomic>
#include <cstdint>

namespace {

constexpr uint32_t kMddiBase = 0xAD600000u;
constexpr uint32_t kMddiSize = 0x00000100u;

constexpr uint32_t kWordCount = kMddiSize / 4u;

/* Linux arch/arm/mach-msm irqs-7x30.h: INT_PMDH, which INT_MDDI_PRI aliases. */
constexpr uint32_t kVicLine = 44u;

/* Linux arch/arm/mach-msm video-msm mddihosti.h: the MDDI host register
   offsets, MDDI_CMD through MDDI_PAD_CAL. */
constexpr uint32_t kRegCmd            = 0x00u;
constexpr uint32_t kRegVersion        = 0x04u;
constexpr uint32_t kRegPriPtr         = 0x08u;
constexpr uint32_t kRegBps            = 0x10u;
constexpr uint32_t kRegSpm            = 0x14u;
constexpr uint32_t kRegInt            = 0x18u;
constexpr uint32_t kRegInten          = 0x1Cu;
constexpr uint32_t kRegRevPtr         = 0x20u;
constexpr uint32_t kRegRevSize        = 0x24u;
constexpr uint32_t kRegStat           = 0x28u;
constexpr uint32_t kRegRevRateDiv     = 0x2Cu;
constexpr uint32_t kRegRevCrcErr      = 0x30u;
constexpr uint32_t kRegTa1Len         = 0x34u;
constexpr uint32_t kRegTa2Len         = 0x38u;
constexpr uint32_t kRegRevPktCnt      = 0x44u;
constexpr uint32_t kRegDriveHi        = 0x48u;
constexpr uint32_t kRegDriveLo        = 0x4Cu;
constexpr uint32_t kRegDispWake       = 0x50u;
constexpr uint32_t kRegRevEncapSz     = 0x54u;
constexpr uint32_t kRegRtdVal         = 0x58u;
constexpr uint32_t kRegPadCtl         = 0x68u;
constexpr uint32_t kRegDriverStartCnt = 0x6Cu;
constexpr uint32_t kRegCoreVer        = 0x8Cu;
constexpr uint32_t kRegPadIoCtl       = 0xA0u;
constexpr uint32_t kRegPadCal         = 0xA4u;

/* Linux arch/arm/mach-msm video-msm mddihosti.h: the MDDI_CMD_* command words
   the host accepts, where the low bit of the hibernate form asks the link to
   hibernate after one empty subframe. */
constexpr uint32_t kCmdPowerdown        = 0x0100u;
constexpr uint32_t kCmdHibernate        = 0x0300u;
constexpr uint32_t kCmdHibernateAfterSf = 0x0301u;
constexpr uint32_t kCmdReset            = 0x0400u;
constexpr uint32_t kCmdDispListen       = 0x0500u;
constexpr uint32_t kCmdDispIgnore       = 0x0501u;
constexpr uint32_t kCmdSendRevEncap     = 0x0600u;
constexpr uint32_t kCmdGetClientCap     = 0x0601u;
constexpr uint32_t kCmdSendRtd          = 0x0700u;
constexpr uint32_t kCmdLinkActive       = 0x0900u;
constexpr uint32_t kCmdPeriodicRevEncap = 0x0A00u;

/* Linux arch/arm/mach-msm video-msm mddihosti.h: MDDI_INT_LINK_ACTIVE and
   MDDI_INT_IN_HIBERNATION, the two the MDDI_INT_LINK_STATE_CHANGES pair names. */
constexpr uint32_t kIntLinkActive    = 0x2000u;
constexpr uint32_t kIntInHibernation = 0x4000u;

/* Linux arch/arm/mach-msm video-msm mddihosti.h: MDDI_STAT_LINK_ACTIVE and
   MDDI_STAT_IN_HIBERNATION. */
constexpr uint32_t kStatLinkActive    = 0x0001u;
constexpr uint32_t kStatInHibernation = 0x0010u;

constexpr uint32_t kIntRevEncapDone = 0x00080000u;

/* Linux arch/arm/mach-msm video-msm mddihosti.h:
   MDDI_INT_PRI_LINK_LIST_DONE. */
constexpr uint32_t kIntPriLinkListDone = 0x8000u;

constexpr uint32_t kCapPacketType   = 66u;
constexpr uint32_t kCapPacketBytes  = 76u;
constexpr uint32_t kCapPacketLength = kCapPacketBytes - 2u;

constexpr uint32_t kCapOffBitmapWidth  = 16u;
constexpr uint32_t kCapOffBitmapHeight = 18u;
constexpr uint32_t kCapOffWindowWidth  = 20u;
constexpr uint32_t kCapOffWindowHeight = 22u;
constexpr uint32_t kCapOffMfrName      = 62u;
constexpr uint32_t kCapOffProductCode  = 64u;

/* Linux arch/arm/mach-msm video-msm mddihosti.h:
   mddi_register_access_packet_type. */
constexpr uint32_t kRegAccPacketType  = 146u;
constexpr uint32_t kRegAccPacketBytes = 18u;
constexpr uint32_t kRegAccPacketLength = kRegAccPacketBytes - 2u;

constexpr uint32_t kPktOffLength   =  0u;
constexpr uint32_t kPktOffType     =  2u;
constexpr uint32_t kPktOffRwInfo   =  6u;
constexpr uint32_t kPktOffAddress  =  8u;
constexpr uint32_t kPktOffDataList = 14u;

/* Linux arch/arm/mach-msm video-msm mddihosti.h: read_write_info bits 15:14
   carry 11 for a response to a read, over the data item count in bits 13:0. */
constexpr uint32_t kRwInfoReadResponse = 0xC001u;

constexpr uint32_t kRevPacketOne   = 1u;
constexpr uint32_t kRevPacketNone  = 0u;
constexpr uint32_t kRevNoCrcErrors = 0u;

constexpr uint32_t kCoreVersion = 0x28u;

constexpr uint32_t kRegReset = 0u;

class Msm8255MddiHost : public Peripheral, public Msm8255MddiLinkListHost {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Msm8255;
    }

    void OnReady() override {
        ResetState();
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            ResetState();
            PublishLine();
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kMddiBase; }
    uint32_t MmioSize() const override { return kMddiSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (off == kRegCoreVer) return kCoreVersion;
        if (off == kRegPadCtl || off == kRegInten || off == kRegInt ||
            off == kRegStat || off == kRegRtdVal ||
            off == kRegRevPktCnt || off == kRegRevCrcErr) {
            return Reg(off);
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off == kRegCmd) {
            WriteCommand(addr, value);
            return;
        }
        /* Linux arch/arm/mach-msm video-msm mddihosti.c mddi_host_isr writes the
           bits it has just handled back to INT, so a set bit clears that
           source. */
        if (off == kRegInt) {
            SetReg(kRegInt, Reg(kRegInt) & ~value);
            PublishLine();
            return;
        }
        if (off == kRegInten) {
            SetReg(kRegInten, value);
            PublishLine();
            return;
        }
        if (off == kRegPriPtr) {
            SetReg(kRegPriPtr, value);
            ExecuteLinkList(value);
            return;
        }
        if (!IsConfigReg(off)) {
            HaltUnsupportedAccess("WriteWord", addr, value);
        }
        SetReg(off, value);
    }

    void SaveState(StateWriter& w) override {
        for (uint32_t i = 0; i < kWordCount; ++i) {
            w.Write<uint32_t>(regs_[i].load(std::memory_order_acquire));
        }
        w.Write<uint32_t>(rev_cursor_.load(std::memory_order_acquire));
        w.Write<uint32_t>(response_pending_.load(std::memory_order_acquire));
        w.Write<uint32_t>(response_address_.load(std::memory_order_acquire));
        w.Write<uint32_t>(response_value_.load(std::memory_order_acquire));
        if (auto* client = emu_.TryGet<Msm8255MddiClient>()) {
            client->SaveState(w);
        }
    }

    void RestoreState(StateReader& r) override {
        for (uint32_t i = 0; i < kWordCount; ++i) {
            uint32_t v = kRegReset;
            r.Read(v);
            regs_[i].store(v, std::memory_order_release);
        }
        RestoreField(r, rev_cursor_);
        RestoreField(r, response_pending_);
        RestoreField(r, response_address_);
        RestoreField(r, response_value_);
        if (auto* client = emu_.TryGet<Msm8255MddiClient>()) {
            client->RestoreState(r);
        }
    }

    void PostRestore() override { PublishLine(); }

private:
    uint32_t Reg(uint32_t off) const {
        return regs_[off / 4u].load(std::memory_order_acquire);
    }

    void SetReg(uint32_t off, uint32_t value) {
        regs_[off / 4u].store(value, std::memory_order_release);
    }

    /* Linux arch/arm/mach-msm video-msm mddihosti.c mddi_host_isr takes the
       pending set as INT masked by INTEN, so the line follows that product. */
    void PublishLine() {
        auto& vic = emu_.Get<IrqController>();
        if ((Reg(kRegInt) & Reg(kRegInten)) != 0u) {
            vic.AssertIrq(kVicLine);
        } else {
            vic.DeAssertIrq(kVicLine);
        }
    }

    void EnterLinkActive() {
        if ((Reg(kRegStat) & kStatLinkActive) != 0u) return;
        SetReg(kRegStat,
               (Reg(kRegStat) & ~kStatInHibernation) | kStatLinkActive);
        SetReg(kRegInt,
               (Reg(kRegInt) & ~kIntInHibernation) | kIntLinkActive);
        PublishLine();
    }

    void EnterHibernation() {
        if ((Reg(kRegStat) & kStatInHibernation) != 0u) return;
        SetReg(kRegStat,
               (Reg(kRegStat) & ~kStatLinkActive) | kStatInHibernation);
        SetReg(kRegInt,
               (Reg(kRegInt) & ~kIntLinkActive) | kIntInHibernation);
        PublishLine();
    }

    void ResetState() {
        for (uint32_t i = 0; i < kWordCount; ++i) {
            regs_[i].store(kRegReset, std::memory_order_release);
        }
        SetReg(kRegStat, kStatInHibernation);
        rev_cursor_.store(0u, std::memory_order_release);
        response_pending_.store(0u, std::memory_order_release);
        response_address_.store(0u, std::memory_order_release);
        response_value_.store(0u, std::memory_order_release);
    }

    static void RestoreField(StateReader& r, std::atomic<uint32_t>& field) {
        uint32_t v = kRegReset;
        r.Read(v);
        field.store(v, std::memory_order_release);
    }

    void ExecuteLinkList(uint32_t head_pa) {
        emu_.Get<Msm8255MddiLinkList>().Execute(head_pa, *this);
        SetReg(kRegInt, Reg(kRegInt) | kIntPriLinkListDone);
        PublishLine();
    }

    void QueueRegisterReadResponse(uint32_t address, uint32_t value) override {
        response_address_.store(address, std::memory_order_release);
        response_value_.store(value, std::memory_order_release);
        response_pending_.store(1u, std::memory_order_release);
    }

    void DeliverReversePacket(const uint8_t* packet, uint32_t bytes) {
        const uint32_t base = Reg(kRegRevPtr);
        if (base == 0u) {
            emu_.Get<Fatal>().Die(
                "msm8255 mddi host: the guest asked the link for reverse data "
                "before it programmed the reverse-packet pointer");
        }
        const uint32_t window = Reg(kRegRevSize);
        if (window < bytes) {
            emu_.Get<Fatal>().Die(
                "msm8255 mddi host: the guest declared a %u-byte reverse packet "
                "buffer and the client answers with %u bytes", window, bytes);
        }

        auto&    mem    = emu_.Get<EmulatedMemory>();
        uint32_t cursor = rev_cursor_.load(std::memory_order_acquire);
        for (uint32_t i = 0; i < bytes; ++i) {
            mem.WriteByte(base + cursor, packet[i]);
            cursor = (cursor + 1u) % window;
        }
        rev_cursor_.store(cursor, std::memory_order_release);
    }

    void CompleteReverseEncap(uint32_t packets) {
        SetReg(kRegRevCrcErr, kRevNoCrcErrors);
        SetReg(kRegRevPktCnt, packets);
        SetReg(kRegInt, Reg(kRegInt) | kIntRevEncapDone);
        PublishLine();
    }

    void DeliverClientCapability() {
        const Msm8255MddiClientCapability cap =
            emu_.Get<Msm8255MddiClient>().Capability();

        uint8_t packet[kCapPacketBytes] = {};
        cerf::le::Put16(packet + kPktOffLength,       static_cast<uint16_t>(kCapPacketLength));
        cerf::le::Put16(packet + kPktOffType,         static_cast<uint16_t>(kCapPacketType));
        cerf::le::Put16(packet + kCapOffBitmapWidth,  static_cast<uint16_t>(cap.bitmap_width));
        cerf::le::Put16(packet + kCapOffBitmapHeight, static_cast<uint16_t>(cap.bitmap_height));
        cerf::le::Put16(packet + kCapOffWindowWidth,  static_cast<uint16_t>(cap.display_window_width));
        cerf::le::Put16(packet + kCapOffWindowHeight, static_cast<uint16_t>(cap.display_window_height));
        cerf::le::Put16(packet + kCapOffMfrName,      static_cast<uint16_t>(cap.mfr_name));
        cerf::le::Put16(packet + kCapOffProductCode,  static_cast<uint16_t>(cap.product_code));

        DeliverReversePacket(packet, kCapPacketBytes);
        CompleteReverseEncap(kRevPacketOne);
    }

    void DeliverReverseEncapsulation() {
        if (response_pending_.load(std::memory_order_acquire) == 0u) {
            CompleteReverseEncap(kRevPacketNone);
            return;
        }

        uint8_t packet[kRegAccPacketBytes] = {};
        cerf::le::Put16(packet + kPktOffLength, static_cast<uint16_t>(kRegAccPacketLength));
        cerf::le::Put16(packet + kPktOffType,   static_cast<uint16_t>(kRegAccPacketType));
        cerf::le::Put16(packet + kPktOffRwInfo, static_cast<uint16_t>(kRwInfoReadResponse));
        cerf::le::Put32(packet + kPktOffAddress,
                        response_address_.load(std::memory_order_acquire));
        cerf::le::Put32(packet + kPktOffDataList,
                        response_value_.load(std::memory_order_acquire));

        response_pending_.store(0u, std::memory_order_release);
        DeliverReversePacket(packet, kRegAccPacketBytes);
        CompleteReverseEncap(kRevPacketOne);
    }

    void WriteCommand(uint32_t addr, uint32_t value) {
        switch (value) {
            case kCmdLinkActive:
                SetReg(kRegCmd, value);
                EnterLinkActive();
                return;
            case kCmdPowerdown:
            case kCmdHibernate:
            case kCmdHibernateAfterSf:
            case kCmdReset:
                SetReg(kRegCmd, value);
                EnterHibernation();
                return;
            case kCmdGetClientCap:
                SetReg(kRegCmd, value);
                DeliverClientCapability();
                return;
            case kCmdSendRevEncap:
                SetReg(kRegCmd, value);
                DeliverReverseEncapsulation();
                return;
            case kCmdDispListen:
            case kCmdDispIgnore:
            case kCmdSendRtd:
            case kCmdPeriodicRevEncap:
                SetReg(kRegCmd, value);
                return;
            default:
                HaltUnsupportedAccess("WriteWord", addr, value);
        }
    }

    static bool IsConfigReg(uint32_t off) {
        switch (off) {
            case kRegVersion:
            case kRegBps:
            case kRegSpm:
            case kRegRevPtr:
            case kRegRevSize:
            case kRegRevRateDiv:
            case kRegTa1Len:
            case kRegTa2Len:
            case kRegDriveHi:
            case kRegDriveLo:
            case kRegDispWake:
            case kRegRevEncapSz:
            case kRegPadCtl:
            case kRegDriverStartCnt:
            case kRegPadIoCtl:
            case kRegPadCal:
                return true;
            default:
                return false;
        }
    }

    std::atomic<uint32_t> regs_[kWordCount] = {};

    std::atomic<uint32_t> rev_cursor_{0};
    std::atomic<uint32_t> response_pending_{0};
    std::atomic<uint32_t> response_address_{0};
    std::atomic<uint32_t> response_value_{0};
};

}

REGISTER_SERVICE(Msm8255MddiHost);
