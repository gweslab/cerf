#include "nec_mobilepro_700_pcic.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/host_widget_registry.h"
#include "../../socs/vr41xx/vr41xx_giu.h"
#include "../../state/state_stream.h"
#include "../board_context.h"
#include "nec_mobilepro_700_id.h"

namespace {

constexpr uint32_t kPortIndex = 0x0u;
constexpr uint32_t kPortData  = 0x1u;

constexpr uint8_t  kRegInterfaceStatus = 0x01u;
constexpr uint8_t  kRegVoltageSelect   = 0x2Fu;
constexpr uint8_t  kCscDetectChange    = 0x08u;
constexpr int      kGiuPin = 9;

/* No enabled window decodes the access: the 16-bit PC Card bus floats high. */
constexpr uint8_t  kFloat8  = 0xFFu;
constexpr uint16_t kFloat16 = 0xFFFFu;

}  /* namespace */

NecMobilePro700Pcic::NecMobilePro700Pcic(CerfEmulator& emu)
    : Service(emu),
      slot0_(emu, *this, L"PCMCIA #1"),
      slot1_(emu, *this, L"PCMCIA #2") {}

bool NecMobilePro700Pcic::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::NecMobilepro700;
}

void NecMobilePro700Pcic::OnReady() {
    auto& reg = emu_.Get<HostWidgetRegistry>();
    reg.Register(&slot0_);
    reg.Register(&slot1_);
}

uint8_t NecMobilePro700Pcic::ReadPcicByte(uint32_t port) {
    uint8_t result;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (port == kPortIndex) return index_;
        result = ReadDataLocked();
    }
    /* A reg 0x04 read read-clears the CSC latch, a combinational-output input, so
       re-evaluate the interrupt line here as on the ExCA write path. */
    UpdateGiuLine();
    return result;
}

void NecMobilePro700Pcic::WritePcicByte(uint32_t port, uint8_t value) {
    int  bank      = 0;
    bool power_on  = false;
    bool power_hit = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (port == kPortIndex) { index_ = value; return; }
        power_hit = WriteDataLocked(value, &bank, &power_on);
    }
    if (power_hit) Slot(bank).SetPowered(power_on);
    /* 82365SL interrupt output is combinational over IREQ# + the reg 0x03 IRQ-steer
       config, so an ExCA config write can assert/deassert it - re-evaluate. */
    UpdateGiuLine();
}

uint8_t NecMobilePro700Pcic::ReadDataLocked() {
    const int bank = index_ >> 6;
    if (bank >= 2) {
        LOG(Caution, "[MP700-PCIC] read of INDEX 0x%02X: only 2 sockets\n", index_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint8_t sub = index_ & 0x3Fu;
    if (Pcic82365::Owns(sub)) {
        if (sub == kRegInterfaceStatus) Exca(bank).SetCardPresent(Slot(bank).HasCard());
        return Exca(bank).ReadReg(sub);
    }
    if (sub == kRegVoltageSelect) return voltage_select_[bank];
    LOG(Caution, "[MP700-PCIC] read of unowned INDEX 0x%02X (socket %d reg 0x%02X)\n",
        index_, bank, sub);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

bool NecMobilePro700Pcic::WriteDataLocked(uint8_t value, int* bank, bool* power_on) {
    const int b = index_ >> 6;
    if (b >= 2) {
        LOG(Caution, "[MP700-PCIC] write of INDEX 0x%02X: only 2 sockets\n", index_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint8_t sub = index_ & 0x3Fu;
    if (Pcic82365::Owns(sub)) {
        *bank = b;
        return Exca(b).WriteReg(sub, value, power_on);
    }
    if (sub == kRegVoltageSelect) { voltage_select_[b] = value; return false; }
    LOG(Caution, "[MP700-PCIC] write of unowned INDEX 0x%02X (socket %d reg 0x%02X) "
        "value 0x%02X\n", index_, b, sub, value);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

bool NecMobilePro700Pcic::DecodeMem(uint32_t off, int* bank, uint32_t* card_addr,
                                    bool* attribute, bool* writable) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    for (int b = 0; b < 2; ++b) {
        if (Exca(b).MapMem(off, card_addr, attribute, writable)) { *bank = b; return true; }
    }
    return false;
}

bool NecMobilePro700Pcic::DecodeIo(uint32_t off, int* bank, uint32_t* card_io) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    for (int b = 0; b < 2; ++b) {
        if (Exca(b).MapIo(off, card_io)) { *bank = b; return true; }
    }
    return false;
}

uint8_t NecMobilePro700Pcic::ReadCardMem8(uint32_t off) {
    int bank; uint32_t addr; bool attribute, writable;
    if (!DecodeMem(off, &bank, &addr, &attribute, &writable)) return kFloat8;
    return attribute ? Slot(bank).ReadAttribute8(addr) : Slot(bank).ReadCommon8(addr);
}

uint16_t NecMobilePro700Pcic::ReadCardMem16(uint32_t off) {
    int bank; uint32_t addr; bool attribute, writable;
    if (!DecodeMem(off, &bank, &addr, &attribute, &writable)) return kFloat16;
    if (attribute) {
        /* Attribute memory drives even bytes only; image the even byte on both
           halves of the 16-bit bus. */
        const uint8_t v = Slot(bank).ReadAttribute8(addr & ~1u);
        return static_cast<uint16_t>((v << 8) | v);
    }
    return Slot(bank).ReadCommon16(addr);
}

void NecMobilePro700Pcic::WriteCardMem8(uint32_t off, uint8_t value) {
    int bank; uint32_t addr; bool attribute, writable;
    if (!DecodeMem(off, &bank, &addr, &attribute, &writable) || !writable) return;
    if (attribute) Slot(bank).WriteAttribute8(addr, value);
    else           Slot(bank).WriteCommon8(addr, value);
}

void NecMobilePro700Pcic::WriteCardMem16(uint32_t off, uint16_t value) {
    int bank; uint32_t addr; bool attribute, writable;
    if (!DecodeMem(off, &bank, &addr, &attribute, &writable) || !writable) return;
    if (attribute) Slot(bank).WriteAttribute8(addr & ~1u, static_cast<uint8_t>(value & 0xFFu));
    else           Slot(bank).WriteCommon16(addr, value);
}

uint8_t NecMobilePro700Pcic::ReadCardIo8(uint32_t off) {
    int bank; uint32_t io;
    if (!DecodeIo(off, &bank, &io)) return kFloat8;
    return Slot(bank).ReadIo8(io);
}

uint16_t NecMobilePro700Pcic::ReadCardIo16(uint32_t off) {
    int bank; uint32_t io;
    if (!DecodeIo(off, &bank, &io)) return kFloat16;
    return Slot(bank).ReadIo16(io);
}

void NecMobilePro700Pcic::WriteCardIo8(uint32_t off, uint8_t value) {
    int bank; uint32_t io;
    if (!DecodeIo(off, &bank, &io)) return;
    Slot(bank).WriteIo8(io, value);
}

void NecMobilePro700Pcic::WriteCardIo16(uint32_t off, uint16_t value) {
    int bank; uint32_t io;
    if (!DecodeIo(off, &bank, &io)) return;
    Slot(bank).WriteIo16(io, value);
}

void NecMobilePro700Pcic::UpdateGiuLine() {
    bool level = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        for (int b = 0; b < 2; ++b) {
            if (Exca(b).DetectChangeInterruptActive()) level = true;
            if (card_irq_[b] && Exca(b).CardIrqRouted())  level = true;
        }
    }
    emu_.Get<Vr41xxGiu>().SetPinLevel(kGiuPin, level);
}

void NecMobilePro700Pcic::OnCardDetectChanged(PcmciaSlot& slot) {
    const int bank = BankOf(slot);
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        Exca(bank).LatchStatusChange(kCscDetectChange);
    }
    UpdateGiuLine();
}

void NecMobilePro700Pcic::OnCardIrqAsserted(PcmciaSlot& slot) {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const int b = BankOf(slot);
        card_irq_[b] = true;
        Exca(b).SetCardIrq(true);
    }
    UpdateGiuLine();
}

void NecMobilePro700Pcic::OnCardIrqDeasserted(PcmciaSlot& slot) {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        const int b = BankOf(slot);
        card_irq_[b] = false;
        Exca(b).SetCardIrq(false);
    }
    UpdateGiuLine();
}

void NecMobilePro700Pcic::SaveState(StateWriter& w) {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        w.Write("index", index_);
        w.Write<uint8_t>("card_irq", card_irq_[0] ? 1u : 0u);
        w.Write<uint8_t>("card_irq", card_irq_[1] ? 1u : 0u);
        w.Write("voltage_select", voltage_select_[0]);
        w.Write("voltage_select", voltage_select_[1]);
        exca0_.SaveState(w);
        exca1_.SaveState(w);
    }
    slot0_.SaveSlotState(w);
    slot1_.SaveSlotState(w);
}

void NecMobilePro700Pcic::RestoreState(StateReader& r) {
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        r.Read("index", index_);
        uint8_t a = 0, b = 0;
        r.Read("card_irq", a); card_irq_[0] = (a != 0);
        r.Read("card_irq", b); card_irq_[1] = (b != 0);
        r.Read("voltage_select", voltage_select_[0]);
        r.Read("voltage_select", voltage_select_[1]);
        exca0_.RestoreState(r);
        exca1_.RestoreState(r);
    }
    slot0_.RestoreSlotState(r);
    slot1_.RestoreSlotState(r);
}

void NecMobilePro700Pcic::PostRestore() {
    slot0_.PostRestoreSlot();
    slot1_.PostRestoreSlot();
}

REGISTER_SERVICE(NecMobilePro700Pcic);
