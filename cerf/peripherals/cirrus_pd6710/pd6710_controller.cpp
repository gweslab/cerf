#include "pd6710_controller.h"

#include "pd6710_card_irq_line.h"
#include "pd6710_management_irq_line.h"

#include "../../boards/board_context.h"
#include "../../boards/smdk2410_devemu/devemu_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/host_widget_registry.h"
#include "../../state/state_stream.h"

namespace {

constexpr uint32_t kPortIndex = 0x0u;
constexpr uint32_t kPortData  = 0x1u;

enum : uint8_t {
    kRegChipRevision    = 0x00,
    kRegInterfaceStatus = 0x01,
    kRegGeneralControl  = 0x16,
    kRegFifoControl     = 0x17,
    kRegGlobalControl   = 0x1E,
    kRegChipInfo        = 0x1F,
};

constexpr uint8_t kCscDetectChange = 0x08u;

}  /* namespace */

Pd6710Controller::Pd6710Controller(CerfEmulator& emu)
    : Service(emu), slot_(emu, *this, L"PCMCIA #1") {}

bool Pd6710Controller::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Devemu;
}

void Pd6710Controller::OnReady() {
    /* CL-PD6710/'22 Data Sheet v3.1 §9.4 "Chip Information" index 1Fh:
       bits 7:6 = '11' on the first read after reset or an I/O write to the
       register, '00' on the next read; bit 5 = 0 single-socket (CL-PD6710). */
    reg_chip_info_ = 0xC0u;

    emu_.Get<HostWidgetRegistry>().Register(&slot_);
}

uint8_t Pd6710Controller::ReadPcicByte(uint32_t port) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    if (port == kPortIndex) return index_;
    return ReadIndexedDataLocked();
}

void Pd6710Controller::WritePcicByte(uint32_t port, uint8_t value) {
    bool power_changed = false;
    bool power_on      = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (port == kPortIndex) {
            index_ = value;
            return;
        }
        power_changed = WriteIndexedDataLocked(value, &power_on);
    }
    if (power_changed) slot_.SetPowered(power_on);
}

uint8_t Pd6710Controller::ReadIndexedDataLocked() {
    if (Pcic82365::Owns(index_)) {
        if (index_ == kRegInterfaceStatus) exca_.SetCardPresent(slot_.HasCard());
        return exca_.ReadReg(index_);
    }
    switch (index_) {
        case kRegChipRevision:  return 0x83u;   /* the BSP driver expects this revision */
        case kRegGeneralControl: return 1u;     /* 5.0 V -> 16-bit card */
        case kRegFifoControl:    return 0u;
        case kRegGlobalControl:  return 0u;
        case kRegChipInfo: {
            const uint8_t v = reg_chip_info_;
            reg_chip_info_ = static_cast<uint8_t>(reg_chip_info_ & ~0xC0u);
            return v;
        }
        default:
            LOG(Caution, "[PD6710] read of unmodeled INDEX 0x%02X\n", index_);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
}

bool Pd6710Controller::WriteIndexedDataLocked(uint8_t value, bool* power_on) {
    if (Pcic82365::Owns(index_)) {
        return exca_.WriteReg(index_, value, power_on);
    }
    switch (index_) {
        case kRegGeneralControl:
        case kRegFifoControl:
        case kRegGlobalControl:
            return false;   /* accepted, no emulated effect */
        case kRegChipInfo:
            reg_chip_info_ = 0xC0u;
            return false;
        default:
            LOG(Caution, "[PD6710] write of unmodeled INDEX 0x%02X "
                    "(value 0x%02X)\n", index_, value);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
}

bool Pd6710Controller::MapIo(uint32_t bus_io, uint32_t* card_io) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return exca_.MapIo(bus_io, card_io);
}

bool Pd6710Controller::MapMem(uint32_t bus_off, uint32_t* card_addr,
                              bool* attribute, bool* writable) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    return exca_.MapMem(bus_off, card_addr, attribute, writable);
}

void Pd6710Controller::OnCardDetectChanged(PcmciaSlot& slot) {
    bool pulse;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        exca_.LatchStatusChange(kCscDetectChange);
        pulse = exca_.DetectChangeIntEnabled();
    }
    if (!slot.HasCard()) {
        if (auto* line = emu_.TryGet<Pd6710CardIrqLine>()) line->Deassert();
    }
    if (pulse) {
        if (auto* line = emu_.TryGet<Pd6710ManagementIrqLine>()) line->Pulse();
    }
}

void Pd6710Controller::OnCardIrqAsserted(PcmciaSlot&) {
    bool enabled;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        enabled = exca_.CardIrqRouted();
    }
    if (!enabled) return;
    if (auto* line = emu_.TryGet<Pd6710CardIrqLine>()) line->Assert();
}

void Pd6710Controller::OnCardIrqDeasserted(PcmciaSlot&) {
    bool enabled;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        enabled = exca_.CardIrqRouted();
    }
    if (!enabled) return;
    if (auto* line = emu_.TryGet<Pd6710CardIrqLine>()) line->Deassert();
}

/* state_mutex_ is dropped before slot_.SaveSlotState: the slot takes bus_mutex_,
   which ranks above state_mutex_ (see WriteIndexedDataLocked). */
void Pd6710Controller::SaveState(StateWriter& w) {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        w.Write("index", index_);
        w.Write("reg_chip_info", reg_chip_info_);
        exca_.SaveState(w);
    }
    slot_.SaveSlotState(w);
}

void Pd6710Controller::RestoreState(StateReader& r) {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        r.Read("index", index_);
        r.Read("reg_chip_info", reg_chip_info_);
        exca_.RestoreState(r);
    }
    slot_.RestoreSlotState(r);
}

void Pd6710Controller::PostRestore() {
    slot_.PostRestoreSlot();
}

REGISTER_SERVICE(Pd6710Controller);
