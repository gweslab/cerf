#include "serial_pccard.h"

#include "../serial/serial_endpoint.h"
#include "../serial/modem_personality.h"
#include "../serial/host_serial_forward.h"

#include "../pcmcia/pcmcia_slot.h"
#include "../../core/cerf_emulator.h"
#include "../../core/string_utils.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"

namespace {

constexpr uint8_t FCR_COR_SRESET = 0x80;
constexpr uint8_t FCR_FCSR_INTR  = 0x02;   /* the bus-driver shared-ISR check bit */

}  /* namespace */

SerialPcCard::SerialPcCard(CerfEmulator& emu) : PcmciaCard(emu) { BuildCis(); }
SerialPcCard::SerialPcCard(CerfEmulator& emu, std::wstring host_com_port)
    : PcmciaCard(emu), mode_(Mode::HostForward),
      host_port_(std::move(host_com_port)) { BuildCis(); }
SerialPcCard::~SerialPcCard() = default;

std::wstring SerialPcCard::TooltipDetail() const {
    if (mode_ == Mode::HostForward)
        return std::wstring(kForwardDisplayName) + L" → host " + host_port_;
    return kDisplayName;
}

void SerialPcCard::BuildCis() {
    cis_ = {0x21, 0x02, 0x02, 0x00};                  /* CISTPL_FUNCID: serial(2) */
    if (mode_ == Mode::Modem) {
        cis_.insert(cis_.end(), {0x22, 0x01, 0x02});  /* CISTPL_FUNCE: data modem */
        cis_.insert(cis_.end(), {                     /* CISTPL_VERS_1 "Virtual Modem" */
            0x15, 0x16, 0x04, 0x01,
                'C', 'E', 'R', 'F', 0x00,
                'V', 'i', 'r', 't', 'u', 'a', 'l', ' ', 'M', 'o', 'd', 'e', 'm', 0x00,
                0xFF,
        });
    } else {
        cis_.insert(cis_.end(), {                     /* CISTPL_VERS_1 "Serial Forwarder" */
            0x15, 0x19, 0x04, 0x01,
                'C', 'E', 'R', 'F', 0x00,
                'S', 'e', 'r', 'i', 'a', 'l', ' ', 'F', 'o', 'r', 'w', 'a', 'r', 'd', 'e', 'r', 0x00,
                0xFF,
        });
    }
    cis_.insert(cis_.end(), {
        0x1A, 0x05, 0x01, 0x01, 0x00, 0x02, 0x03,     /* CISTPL_CONFIG        */
        0x1B, 0x08, 0xC1, 0x01, 0x08, 0xAA, 0x60,
            0xF8, 0x03, 0x07,                         /* CISTPL_CFTABLE_ENTRY */
        0xFF,                                         /* CISTPL_END           */
    });
}

void SerialPcCard::OnInserted() {
    if (mode_ == Mode::HostForward) {
        auto fwd = std::make_unique<HostSerialForward>(host_port_, emu_);
        PcmciaSlot* slot = slot_;
        const uint64_t id = card_id_;
        fwd->SetOnBridgeDead([slot, id] { slot->EjectCardIfResident(id); });
        endpoint_ = std::move(fwd);
    } else {
        endpoint_ = std::make_unique<ModemPersonality>(
            emu_, "ppp:" + WideToUtf8(slot_->WidgetName()));
    }
    /* OUT2 drives the card's tri-state buffer onto the socket IRQ line, so the card
       raises no interrupt until the driver sets it. That gate is this card's wiring,
       not the UART's: PC16550D §8.6.7 bit 3 makes OUT2 "an auxiliary user-designated
       output" with no interrupt role inside the part. */
    uart_ = std::make_unique<Serial16550>(
        endpoint_.get(), [this](bool a) { OnUartIrq(a); },
        Serial16550::Config{/*ier_mask=*/0x0Fu,
                            /*irq_gate_mcr=*/0x08u,
                            /*irq_gate_ier=*/0u});
    uart_->SetActivityWidget(slot_);
    endpoint_->BindUart(*uart_);
}

void SerialPcCard::OnShutdown() {
    DriveIrqLineLow();
    if (uart_) uart_->SetEndpoint(nullptr);
    endpoint_.reset();
}

void SerialPcCard::PowerOn () {
    powered_ = true;
    uart_->Reset();
    if (endpoint_) endpoint_->OnOpen();
}

void SerialPcCard::PowerOff() {
    DriveIrqLineLow();
    if (endpoint_) endpoint_->OnClose();
}

void SerialPcCard::DriveIrqLineLow() {
    const bool was_driving = powered_;
    powered_ = false;
    fcsr_ &= (uint8_t)~FCR_FCSR_INTR;
    if (was_driving && uart_irq_) slot_->ClearIrq();
    uart_irq_ = false;
}

void SerialPcCard::OnUartIrq(bool asserted) {
    if (!powered_) return;
    uart_irq_ = asserted;
    if (asserted) { fcsr_ |= FCR_FCSR_INTR; slot_->RaiseIrq(); }
    else          { fcsr_ &= (uint8_t)~FCR_FCSR_INTR; slot_->ClearIrq(); }
}

uint8_t SerialPcCard::ReadAttribute8(uint32_t offset) {
    /* CIS in attribute memory, 8-bit aliased across even bytes (tuple byte n at
       offset 2n), then the config registers. */
    uint8_t v = 0xFFu;
    if (offset < cis_.size() * 2u)   v = cis_[offset / 2u];
    else if (offset == kCorOffset)   v = cor_;
    else if (offset == kFcsrOffset)  v = fcsr_;
    return v;
}

void SerialPcCard::WriteAttribute8(uint32_t offset, uint8_t value) {
    if (offset == kCorOffset) {
        cor_ = value;
        if (value & FCR_COR_SRESET) uart_->Reset();
        return;
    }
    if (offset == kFcsrOffset) {
        /* Host writes the status config; the INTR bit stays owned by the UART. */
        fcsr_ = (uint8_t)((value & (uint8_t)~FCR_FCSR_INTR) |
                          (uart_irq_ ? FCR_FCSR_INTR : 0u));
        return;
    }
    /* CIS is ROM; ignore other writes. */
}

uint8_t  SerialPcCard::ReadCommon8  (uint32_t)            { return 0xFFu;   }
uint16_t SerialPcCard::ReadCommon16 (uint32_t)            { return 0xFFFFu; }
void     SerialPcCard::WriteCommon8 (uint32_t, uint8_t)   {}
void     SerialPcCard::WriteCommon16(uint32_t, uint16_t)  {}

/* serial.dll reaches the 16550 through the mapped I/O window at the configured
   base (0x3F8), as 8-bit READ/WRITE_PORT_UCHAR accesses to registers 0..7. */
uint8_t SerialPcCard::ReadIo8(uint32_t offset) {
    if (offset - kIoBase < kRegCount) return uart_->ReadReg8(offset - kIoBase);
    return 0xFFu;
}
void SerialPcCard::WriteIo8(uint32_t offset, uint8_t value) {
    if (offset - kIoBase < kRegCount) uart_->WriteReg8(offset - kIoBase, value);
}
uint16_t SerialPcCard::ReadIo16(uint32_t offset) {
    return (uint16_t)(ReadIo8(offset) | (ReadIo8(offset + 1u) << 8));
}
/* mode_/host_port_/cis_/endpoint_ are identity / host binding; the PCMCIA
   config regs + the 16550 UART register file are the card state. uart_ is
   built in OnInserted so it always exists while the card sits in a slot. */
void SerialPcCard::SaveState(StateWriter& w) {
    w.Write("cor", cor_); w.Write("fcsr", fcsr_);
    w.Write<uint8_t>("uart_irq", uart_irq_ ? 1u : 0u);
    w.Write<uint8_t>("powered", powered_ ? 1u : 0u);
    uart_->SaveState(w);
}

void SerialPcCard::RestoreState(StateReader& r) {
    r.Read("cor", cor_); r.Read("fcsr", fcsr_);
    uint8_t irq = 0; r.Read("uart_irq", irq); uart_irq_ = (irq != 0);
    uint8_t pwr = 0; r.Read("powered", pwr); powered_ = (pwr != 0);
    uart_->RestoreState(r);
}

void SerialPcCard::PostRestore() {
    uart_->RepublishIrq();
}

void SerialPcCard::WriteIo16(uint32_t offset, uint16_t value) {
    WriteIo8(offset, (uint8_t)(value & 0xFFu));
    WriteIo8(offset + 1u, (uint8_t)(value >> 8));
}
