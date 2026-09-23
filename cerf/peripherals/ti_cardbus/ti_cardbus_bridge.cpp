#include "../pci/pci_device.h"
#include "../pci/pci_host_bridge.h"
#include "../pcic82365/pcic82365.h"
#include "../pcmcia/pcmcia_slot.h"
#include "../pcmcia/pcmcia_auto_insert.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../boards/nec_rockhopper/nec_rockhopper_id.h"
#include "../../host/host_widget_registry.h"
#include "../../socs/vrc5477/vrc5477_intc.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>


namespace {

constexpr uint32_t kVendorId   = 0x104Cu;
constexpr uint32_t kDeviceId   = 0xAC1Cu;
constexpr uint32_t kClassCode  = 0x06070000u;   /* base 0x06 / sub 0x07 / progif 0 / rev 0 = CardBus bridge */
constexpr uint32_t kHeaderType = 0x00020000u;   /* header type 2 (CardBus) at config byte 0x0E, single function */
constexpr uint8_t  kPciDev     = 10u;
constexpr uint32_t kIntPin     = 1u;            /* INTA# */
constexpr uint32_t kIrqInta    = 8u;            /* IRQ_INTA, the VRC5477 INTC source for bus-0 PCI Slot 2 INTA# */

constexpr uint32_t kSocketBarSize  = 0x1000u;
constexpr uint32_t kExCaWindowBase   = 0x800u;
constexpr uint8_t  kExCaChipRevision = 0x84u;
constexpr uint32_t kSockEvent        = 0x00u;   /* W1C event latch */
constexpr uint32_t kSockMask         = 0x04u;
constexpr uint32_t kSockPresentState = 0x08u;   /* read-only */
constexpr uint32_t kSockForceEvent   = 0x0Cu;
constexpr uint32_t kSockControl      = 0x10u;

constexpr uint32_t kEvtCardDetect = 0x06u;      /* SEV_CCDETECT1 | SEV_CCDETECT2 */
constexpr uint32_t kEvtAll        = 0x0Fu;

constexpr uint32_t kSpsCcd1       = 0x02u;
constexpr uint32_t kSpsCcd2       = 0x04u;
constexpr uint32_t kSpsPowerCycle = 0x08u;
constexpr uint32_t kSps16BitCard  = 0x10u;
constexpr uint32_t kSpsReady      = 0x40u;
constexpr uint32_t kSps5VCard     = 0x400u;
constexpr uint32_t kSps5VSocket   = 0x10000000u;
constexpr uint32_t kSps3VSocket   = 0x20000000u;

/* CardBus Socket/ExCA base, config offset 0x10: a 32-bit memory BAR. */
struct Bar {
    uint32_t size_mask = 0;
    uint32_t base      = 0;
    uint32_t Read() const { return size_mask ? base : 0u; }
    void Write(uint32_t v) { if (size_mask) base = v & size_mask; }
};

class TiCardbusBridge : public Service, public PciDevice, public PcmciaSlotHost {
public:
    TiCardbusBridge(CerfEmulator& emu) : Service(emu), slot_(emu, *this, L"PCMCIA") {}

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NecRockhopper;
    }
    void OnReady() override {
        std::memset(cfg_, 0, sizeof(cfg_));
        socket_bar_ = { ~(kSocketBarSize - 1u), 0u };
        emu_.Get<PciHostBridge>().RegisterPciDevice(this);
        emu_.Get<HostWidgetRegistry>().Register(&slot_);
        emu_.Get<PcmciaAutoInsert>().InsertDefaultNetworkCard(slot_);
    }
    void OnShutdown() override { slot_.OnShutdown(); }

    uint8_t PciDev() const override { return kPciDev; }
    uint8_t PciFnc() const override { return 0u; }

    uint32_t ConfigRead(uint32_t reg) override {
        switch (reg) {
            case 0x00: return kVendorId | (kDeviceId << 16);
            case 0x08: return kClassCode;
            case 0x0C: return kHeaderType;
            case 0x10: return socket_bar_.Read();
            case 0x3C: return (cfg_[0x3C >> 2] & 0xFFFF00FFu) | (kIntPin << 8);  /* InterruptPin RO */
            default:   return cfg_[reg >> 2];
        }
    }
    void ConfigWrite(uint32_t reg, uint32_t value) override {
        if (reg == 0x10) { socket_bar_.Write(value); return; }
        if (reg == 0x00 || reg == 0x08 || reg == 0x0C) return;   /* read-only identity */
        cfg_[reg >> 2] = value;
    }

    bool MemClaims(uint32_t addr) const override {
        return SocketBarHit(addr) || CardMemHit(addr);
    }
    uint32_t MemRead(uint32_t addr, unsigned size) override {
        if (CardMemHit(addr)) return CardMemRead(addr, size);
        const uint32_t off = addr - socket_bar_.base;
        if (off >= kExCaWindowBase) return ExCaRead(off - kExCaWindowBase, size);
        return SocketRead(off);
    }
    void MemWrite(uint32_t addr, uint32_t value, unsigned size) override {
        if (CardMemHit(addr)) { CardMemWrite(addr, value, size); return; }
        const uint32_t off = addr - socket_bar_.base;
        if (off >= kExCaWindowBase) { ExCaWrite(off - kExCaWindowBase, value, size); return; }
        SocketWrite(off, value);
    }

    bool IoClaims(uint32_t pci_io) const override {
        std::lock_guard<std::mutex> lk(mtx_);
        uint32_t card; return exca_.MapIo(pci_io, &card);
    }
    uint32_t IoRead(uint32_t pci_io, unsigned size) override {
        uint32_t card = 0; bool mapped;
        { std::lock_guard<std::mutex> lk(mtx_); mapped = exca_.MapIo(pci_io, &card); }
        if (!mapped) return cerf::ByteWidthMask(size);
        const uint32_t v = (size >= 2) ? slot_.ReadIo16(card) : slot_.ReadIo8(card);
        return v;
    }
    void IoWrite(uint32_t pci_io, uint32_t value, unsigned size) override {
        uint32_t card = 0; bool mapped;
        { std::lock_guard<std::mutex> lk(mtx_); mapped = exca_.MapIo(pci_io, &card); }
        if (!mapped) return;
        if (size >= 2) slot_.WriteIo16(card, static_cast<uint16_t>(value));
        else           slot_.WriteIo8(card, static_cast<uint8_t>(value));
    }

    void OnCardDetectChanged(PcmciaSlot&) override {
        const bool present = slot_.HasCard();
        bool changed, assert_now;
        { std::lock_guard<std::mutex> lk(mtx_);
          exca_.SetCardPresent(present);
          exca_.LatchStatusChange(0x08u);
          socket_event_ |= kEvtCardDetect;       /* CardBus-socket path for CardBus-aware cards */
          ApplyIrqLocked(&changed, &assert_now); }
        DriveLine(changed, assert_now);
    }
    void OnCardIrqAsserted  (PcmciaSlot&) override { SetCardIrq(true); }
    void OnCardIrqDeasserted(PcmciaSlot&) override { SetCardIrq(false); }

    void SaveState(StateWriter& w) override {
        { std::lock_guard<std::mutex> lk(mtx_);
          w.WriteBytes(cfg_, sizeof(cfg_));
          w.WriteBytes(&socket_bar_, sizeof(socket_bar_));
          w.Write(socket_event_); w.Write(socket_mask_); w.Write(socket_control_);
          w.Write<uint32_t>(card_irq_ ? 1u : 0u);
          /* the driven INTA# level: serialized so a post-restore card deassert
             isn't dropped by a stale edge-detect (stuck source). */
          w.Write<uint32_t>(irq_asserted_ ? 1u : 0u);
          w.WriteBytes(exca_chip_regs_, sizeof(exca_chip_regs_));
          exca_.SaveState(w); }
        slot_.SaveSlotState(w);
    }
    void RestoreState(StateReader& r) override {
        { std::lock_guard<std::mutex> lk(mtx_);
          r.ReadBytes(cfg_, sizeof(cfg_));
          r.ReadBytes(&socket_bar_, sizeof(socket_bar_));
          r.Read(socket_event_); r.Read(socket_mask_); r.Read(socket_control_);
          uint32_t ci = 0; r.Read(ci); card_irq_ = ci != 0;
          uint32_t ia = 0; r.Read(ia); irq_asserted_ = ia != 0;
          r.ReadBytes(exca_chip_regs_, sizeof(exca_chip_regs_));
          exca_.RestoreState(r); }
        slot_.RestoreSlotState(r);
    }

    void PostRestore() override { slot_.PostRestoreSlot(); }

private:
    uint32_t PresentStateLocked() const {
        if (!slot_.HasCard()) {
            return kSpsCcd1 | kSpsCcd2 | kSps5VSocket | kSps3VSocket;   /* both CCD set = no card */
        }
        uint32_t v = kSps16BitCard | kSpsReady | kSps5VCard | kSps5VSocket | kSps3VSocket;
        if (slot_.IsPowered()) v |= kSpsPowerCycle;
        return v;   /* CCD clear + SPS_CB_CARD clear = 16-bit card inserted */
    }

    bool SocketBarHit(uint32_t addr) const {
        const uint32_t b = socket_bar_.base;
        return b && addr >= b && addr < b + kSocketBarSize;
    }
    bool CardMemHit(uint32_t addr) const {
        std::lock_guard<std::mutex> lk(mtx_);
        uint32_t card; bool attr, wr;
        return exca_.MapMem(addr, &card, &attr, &wr);
    }
    uint32_t CardMemRead(uint32_t addr, unsigned size) {
        uint32_t card = 0; bool attr = false, wr = false, mapped;
        { std::lock_guard<std::mutex> lk(mtx_); mapped = exca_.MapMem(addr, &card, &attr, &wr); }
        if (!mapped) return cerf::ByteWidthMask(size);
        const uint32_t v = attr ? slot_.ReadAttribute8(card)
                                : (size >= 2 ? slot_.ReadCommon16(card) : slot_.ReadCommon8(card));
        return v;
    }
    void CardMemWrite(uint32_t addr, uint32_t value, unsigned size) {
        uint32_t card = 0; bool attr = false, wr = false, mapped;
        { std::lock_guard<std::mutex> lk(mtx_); mapped = exca_.MapMem(addr, &card, &attr, &wr); }
        if (!mapped || !wr) return;
        if (attr)               slot_.WriteAttribute8(card, static_cast<uint8_t>(value));
        else if (size >= 2)     slot_.WriteCommon16(card, static_cast<uint16_t>(value));
        else                    slot_.WriteCommon8(card, static_cast<uint8_t>(value));
    }

    uint32_t SocketRead(uint32_t off) {
        std::lock_guard<std::mutex> lk(mtx_);
        switch (off) {
            case kSockEvent:        return socket_event_;
            case kSockMask:         return socket_mask_;
            case kSockPresentState: return PresentStateLocked();
            case kSockControl:      return socket_control_;
            default:                return 0u;
        }
    }
    void SocketWrite(uint32_t off, uint32_t value) {
        bool changed, assert_now;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            switch (off) {
                case kSockEvent:      socket_event_ &= ~value;             break;  /* W1C */
                case kSockMask:       socket_mask_ = value;                break;
                case kSockForceEvent: socket_event_ |= (value & kEvtAll); break;
                case kSockControl:    socket_control_ = value;            break;
                default:              break;                                       /* present-state RO */
            }
            ApplyIrqLocked(&changed, &assert_now);
        }
        DriveLine(changed, assert_now);
    }

    void SetCardIrq(bool on) {
        bool changed, assert_now;
        { std::lock_guard<std::mutex> lk(mtx_);
          card_irq_ = on;
          ApplyIrqLocked(&changed, &assert_now); }
        DriveLine(changed, assert_now);
    }

    /* The 16-bit card's functional IREQ reaches the bridge INTx only when the ExCA
       int/gen register routes it (INT_AND_GENERAL_CONTROL low nibble). */
    uint32_t ExCaRead(uint32_t idx, unsigned size) {
        if (idx == 0x01u) {                       /* INTERFACE_STATUS needs live card-present */
            const bool present = slot_.HasCard();
            std::lock_guard<std::mutex> lk(mtx_);
            exca_.SetCardPresent(present);
            return exca_.ReadReg(0x01u);
        }
        if (Pcic82365::Owns(static_cast<uint8_t>(idx))) {
            uint32_t v; bool changed, assert_now;
            { std::lock_guard<std::mutex> lk(mtx_);
              v = exca_.ReadReg(static_cast<uint8_t>(idx));    /* CARD_STATUS_CHANGE read-clears -> mgmt IRQ may drop */
              ApplyIrqLocked(&changed, &assert_now); }
            DriveLine(changed, assert_now);
            return v;
        }
        if (idx == 0x00u) return kExCaChipRevision;   /* chip-identity, validated by the driver */
        if (IsChipCtrl(idx)) {
            std::lock_guard<std::mutex> lk(mtx_);
            return exca_chip_regs_[idx & 0x3Fu];
        }
        ExCaFatal("read", idx, 0, size);
    }
    void ExCaWrite(uint32_t idx, uint32_t value, unsigned size) {
        if (Pcic82365::Owns(static_cast<uint8_t>(idx))) {
            bool power_changed = false, power_on = false, irq_changed = false, assert_now = false;
            {
                std::lock_guard<std::mutex> lk(mtx_);
                power_changed = exca_.WriteReg(static_cast<uint8_t>(idx),
                                               static_cast<uint8_t>(value), &power_on);
                if (power_changed && power_on) socket_event_ |= kSpsPowerCycle;
                ApplyIrqLocked(&irq_changed, &assert_now);   /* int/gen write may (un)route the card IRQ */
            }
            if (power_changed) slot_.SetPowered(power_on);
            DriveLine(irq_changed, assert_now);
            return;
        }
        if (idx == 0x00u) return;                     /* chip revision: read-only */
        if (IsChipCtrl(idx)) {
            std::lock_guard<std::mutex> lk(mtx_);
            exca_chip_regs_[idx & 0x3Fu] = static_cast<uint8_t>(value);
            return;
        }
        ExCaFatal("write", idx, value, size);
    }
    static bool IsChipCtrl(uint32_t idx) {
        return idx == 0x16u || idx == 0x17u || idx == 0x1Eu || idx == 0x1Fu;
    }

    void ApplyIrqLocked(bool* changed, bool* assert_now) {
        const bool t_sock = (socket_event_ & socket_mask_ & kEvtAll) != 0u;
        const bool t_card = card_irq_ && exca_.CardIrqRouted();
        const bool t_csc  = exca_.DetectChangeInterruptActive();
        const bool active = t_sock || t_card || t_csc;
        *changed    = active != irq_asserted_;
        irq_asserted_ = active;
        *assert_now = active;
    }
    void DriveLine(bool changed, bool assert_now) {
        if (!changed) return;
        auto& intc = emu_.Get<Vrc5477Intc>();
        if (assert_now) intc.AssertSource(kIrqInta);
        else            intc.DeassertSource(kIrqInta);
    }

    [[noreturn]] void ExCaFatal(const char* op, uint32_t exca_off, uint32_t value, unsigned size) {
        LOG(Caution, "TiCardbusBridge: unimplemented ExCA register %s off=0x%02X "
            "value=0x%08X size=%u\n", op, exca_off, value, size);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    PcmciaSlot slot_;
    mutable std::mutex mtx_;
    Pcic82365  exca_;

    uint32_t cfg_[64]          = {};
    uint8_t  exca_chip_regs_[0x40] = {};   /* non-core ExCA chip-control latches (0x16/0x17/0x1E/0x1F) */
    Bar      socket_bar_;
    uint32_t socket_event_   = 0;
    uint32_t socket_mask_    = 0;
    uint32_t socket_control_ = 0;
    bool     card_irq_       = false;
    bool     irq_asserted_   = false;
};

REGISTER_SERVICE(TiCardbusBridge);

}  /* namespace */
