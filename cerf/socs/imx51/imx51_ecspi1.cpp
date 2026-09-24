#include "imx51_ecspi1.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../irq_controller.h"
#include "../spi_slave.h"

namespace {

constexpr uint32_t kBase    = 0x70010000u;
constexpr uint32_t kSize    = 0x00004000u;  /* SPBA0 slot */
constexpr int      kTzicSrc = 36;           /* MCIMX51RM Table 3-2; ipdacp.dll sub_C0D83F80(1) */

/* Register offsets (MCIMX51RM Table 26-3). */
constexpr uint32_t kRxData    = 0x00u;
constexpr uint32_t kTxData    = 0x04u;
constexpr uint32_t kConReg    = 0x08u;
constexpr uint32_t kConfigReg = 0x0Cu;
constexpr uint32_t kIntReg    = 0x10u;
constexpr uint32_t kDmaReg    = 0x14u;
constexpr uint32_t kStatReg   = 0x18u;
constexpr uint32_t kPeriodReg = 0x1Cu;
constexpr uint32_t kTestReg   = 0x20u;
constexpr uint32_t kMsgData   = 0x24u;

/* CONREG fields (MCIMX51RM Table 26-8). */
constexpr uint32_t kConEn  = 1u << 0;  /* enable */
constexpr uint32_t kConXch = 1u << 2;  /* exchange (SMC=0): set to start a burst, self-clears */
constexpr uint32_t kConBurstShift = 20; /* BURST_LENGTH[31:20] = bits-in-burst minus 1 */

/* STATREG fields (MCIMX51RM Table 26-12). */
constexpr uint32_t kStTe  = 1u << 0;  /* TXFIFO empty */
constexpr uint32_t kStTdr = 1u << 1;  /* TXFIFO data request */
constexpr uint32_t kStTf  = 1u << 2;  /* TXFIFO full */
constexpr uint32_t kStRr  = 1u << 3;  /* RXFIFO ready (>=1 word) */
constexpr uint32_t kStRdr = 1u << 4;  /* RXFIFO data request */
constexpr uint32_t kStRf  = 1u << 5;  /* RXFIFO full */
constexpr uint32_t kStRo  = 1u << 6;  /* RXFIFO overflow (W1C) */
constexpr uint32_t kStTc  = 1u << 7;  /* transfer complete (W1C) */

constexpr std::size_t kFifoDepth = 64;  /* MCIMX51RM §26.1: 64x32 TX/RX FIFO */

}  /* namespace */

bool Imx51Ecspi1::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Imx51;
}

void Imx51Ecspi1::OnReady() { emu_.Get<PeripheralDispatcher>().Register(this); }

uint32_t Imx51Ecspi1::MmioBase() const { return kBase; }
uint32_t Imx51Ecspi1::MmioSize() const { return kSize; }

void Imx51Ecspi1::RecomputeStatus() {
    uint32_t s = statreg_ & (kStRo | kStTc);   /* RO/TC are event/W1C bits */
    if (tx_fifo_.empty())               s |= kStTe | kStTdr;
    if (tx_fifo_.size() >= kFifoDepth)  s |= kStTf;
    if (!rx_fifo_.empty())              s |= kStRr | kStRdr;
    if (rx_fifo_.size() >= kFifoDepth)  s |= kStRf;
    statreg_ = s;
}

void Imx51Ecspi1::RaiseIrqIfPending() {
    auto* intc = emu_.TryGet<IrqController>();
    if (!intc) return;
    /* eCSPI asserts its line while any enabled status bit (STATREG & INTREG) is
       set - STATREG/INTREG share bit positions (Tables 26-10/26-12). */
    const bool want = (statreg_ & intreg_ & 0xFFu) != 0u;
    if (want) intc->AssertIrq(kTzicSrc);
    else      intc->DeAssertIrq(kTzicSrc);
}

void Imx51Ecspi1::DoExchange() {
    /* BURST_LENGTH is bits-1; the driver packs each FIFO word little-endian
       (ipdacp.dll sub_C0D83334), so extract bytes LSB-first to hand the slave the
       driver's logical byte order ([reg][len][data]); reassemble RX the same way. */
    const uint32_t burst_bits = ((conreg_ >> kConBurstShift) & 0xFFFu) + 1u;
    const uint32_t nbytes = (burst_bits + 7u) / 8u;
    while (!tx_fifo_.empty()) {
        const uint32_t tx_word = tx_fifo_.front();
        tx_fifo_.pop_front();
        uint32_t rx_word = 0;
        for (uint32_t k = 0; k < nbytes && k < 4u; ++k) {
            const uint8_t tx = static_cast<uint8_t>(tx_word >> (8u * k));
            const uint8_t rx = slave_ ? slave_->Exchange(tx) : 0xFFu;
            rx_word |= static_cast<uint32_t>(rx) << (8u * k);
        }
        if (rx_fifo_.size() < kFifoDepth) rx_fifo_.push_back(rx_word);
        else statreg_ |= kStRo;  /* RXFIFO overflow */
    }
    statreg_ |= kStTc;  /* burst complete */
}

uint32_t Imx51Ecspi1::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    switch (off) {
        case kRxData: {
            uint32_t v = 0;
            if (!rx_fifo_.empty()) { v = rx_fifo_.front(); rx_fifo_.pop_front(); }
            RecomputeStatus();
            RaiseIrqIfPending();
            return v;
        }
        case kConReg:    return conreg_;
        case kConfigReg: return configreg_;
        case kIntReg:    return intreg_;
        case kDmaReg:    return dmareg_;
        case kStatReg:   RecomputeStatus(); return statreg_;
        case kPeriodReg: return periodreg_;
        case kTestReg:   return testreg_;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Imx51Ecspi1::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - kBase;
    switch (off) {
        case kTxData:
            if (tx_fifo_.size() < kFifoDepth) tx_fifo_.push_back(value);
            RecomputeStatus();
            return;
        case kConReg:
            conreg_ = value;
            if (!(value & kConEn)) {           /* clearing EN resets the logic (Table 26-8) */
                tx_fifo_.clear();
                rx_fifo_.clear();
            } else if (value & kConXch) {       /* XCH starts the burst, then self-clears */
                DoExchange();
                conreg_ &= ~kConXch;
            }
            RecomputeStatus();
            RaiseIrqIfPending();
            return;
        case kConfigReg: configreg_ = value; return;
        case kIntReg:    intreg_ = value; RaiseIrqIfPending(); return;
        case kDmaReg:    dmareg_ = value; return;
        case kStatReg:   statreg_ &= ~(value & (kStRo | kStTc)); RaiseIrqIfPending(); return;  /* W1C */
        case kPeriodReg: periodreg_ = value; return;
        case kTestReg:   testreg_ = value; return;
        case kMsgData:   return;  /* write-only message data; unused by the iPod driver */
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void Imx51Ecspi1::SaveState(StateWriter& w) {
    w.Write("conreg", conreg_);   w.Write("configreg", configreg_); w.Write("intreg", intreg_);
    w.Write("dmareg", dmareg_);   w.Write("statreg", statreg_);   w.Write("periodreg", periodreg_);
    w.Write("testreg", testreg_);
    w.Write("tx_fifo_count", static_cast<uint32_t>(tx_fifo_.size()));
    for (uint32_t v : tx_fifo_) w.Write("tx_fifo", v);
    w.Write("rx_fifo_count", static_cast<uint32_t>(rx_fifo_.size()));
    for (uint32_t v : rx_fifo_) w.Write("rx_fifo", v);
    if (auto* s = slave_) s->SaveState(w);
}

void Imx51Ecspi1::RestoreState(StateReader& r) {
    r.Read("conreg", conreg_);   r.Read("configreg", configreg_); r.Read("intreg", intreg_);
    r.Read("dmareg", dmareg_);   r.Read("statreg", statreg_);   r.Read("periodreg", periodreg_);
    r.Read("testreg", testreg_);
    tx_fifo_.clear();
    rx_fifo_.clear();
    uint32_t n = 0;
    r.Read("tx_fifo_count", n);
    for (uint32_t i = 0; i < n; ++i) { uint32_t v = 0; r.Read("tx_fifo", v); tx_fifo_.push_back(v); }
    r.Read("rx_fifo_count", n);
    for (uint32_t i = 0; i < n; ++i) { uint32_t v = 0; r.Read("rx_fifo", v); rx_fifo_.push_back(v); }
    if (auto* s = slave_) s->RestoreState(r);
}

/* Re-drive the TZIC line from the restored STATREG/INTREG: the eCSPI is a
   level-driving interrupt source, so a restore that only reloads registers
   leaves the INTC unaware of a pending IRQ (hibernation.md PostRestore). */
void Imx51Ecspi1::PostRestore() { RaiseIrqIfPending(); }

REGISTER_SERVICE(Imx51Ecspi1);
