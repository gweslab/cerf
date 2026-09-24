#include "casio_cassiopeia_em500_modem.h"

#include "../../core/log.h"
#include "../../state/state_stream.h"

namespace {

/* serial.dll dword_F58130[0]=0x600 (reg-index 0), RMW set-bit7 sub_F56D38. */
constexpr uint32_t kOffCtrl8600 = 0x8600u;

/* serial.dll modem-socket control latches, RMW read-back (base mapper sub_F56C38
   @0xF56C94; sub_F51B94, read = read-back, no consumed status): 0xA1C0 bit2
   sub_F56D10 @0xF56D2A/sub_F56D60 @0xF56DF6; 0xA1C4 bit1 sub_F56D60 @0xF56DEA. */
constexpr uint32_t kOffSocketA1C0 = 0xA1C0u;
constexpr uint32_t kOffSocketA1C4 = 0xA1C4u;

/* nk_main_kernel.exe sub_9F08EE0C @0x9F08EF04 case 19 (SYSINTR 19): word RMW
   `MEMORY[0xAA008684] |= 8` sets 16550 IER bit3 (EDSSI). 0x8684 = 16550 reg 1
   (serial.dll dword_F58130); word access aliases the byte IER. */
constexpr uint32_t kOffIer8684 = 0x8684u;

}  /* namespace */

void CasioCassiopeiaEm500Modem::Init() {
    uart_ = std::make_unique<Serial16550>(
        nullptr, [this](bool a) { OnUartIrq(a); }, Serial16550::Config{});
}

bool CasioCassiopeiaEm500Modem::TryReadByte(uint32_t off, uint8_t& out) {
    if (In16550(off)) { out = uart_->ReadReg8((off - k16550Base) / 4u); return true; }
    if (off == kOffCtrl8600) { out = ctrl_8600_; return true; }
    return false;
}

bool CasioCassiopeiaEm500Modem::TryWriteByte(uint32_t off, uint8_t value) {
    if (In16550(off)) { uart_->WriteReg8((off - k16550Base) / 4u, value); return true; }
    if (off == kOffCtrl8600) { ctrl_8600_ = value; return true; }
    return false;
}

bool CasioCassiopeiaEm500Modem::TryReadHalf(uint32_t off, uint16_t& out) {
    if (off == kOffSocketA1C0) { out = socket_a1c0_; return true; }
    if (off == kOffSocketA1C4) { out = socket_a1c4_; return true; }
    return false;
}

bool CasioCassiopeiaEm500Modem::TryWriteHalf(uint32_t off, uint16_t value) {
    if (off == kOffSocketA1C0) { socket_a1c0_ = value; return true; }
    if (off == kOffSocketA1C4) { socket_a1c4_ = value; return true; }
    return false;
}

bool CasioCassiopeiaEm500Modem::TryReadWord(uint32_t off, uint32_t& out) {
    if (off == kOffIer8684) { out = uart_->ReadReg8((kOffIer8684 - k16550Base) / 4u); return true; }
    return false;
}

bool CasioCassiopeiaEm500Modem::TryWriteWord(uint32_t off, uint32_t value) {
    if (off == kOffIer8684) {
        uart_->WriteReg8((kOffIer8684 - k16550Base) / 4u, static_cast<uint8_t>(value));
        return true;
    }
    return false;
}

void CasioCassiopeiaEm500Modem::OnUartIrq(bool asserted) {
    if (!asserted) return;
    /* nk_main_kernel.exe cascade 0x9F036130: companion 0x0004 bit4 -> loc_9F0369A4
       li $a0,0x13 (SYSINTR 19). */
    LOG(Caution, "EM-500 companion modem 16550 asserted INTR: companion->GIU "
                 "cascade (0x0004 bit4 -> SYSINTR 19) not yet modeled\n");
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

void CasioCassiopeiaEm500Modem::SaveState(StateWriter& w) const {
    w.Write("ctrl_8600", ctrl_8600_);
    w.Write("socket_a1c0", socket_a1c0_);
    w.Write("socket_a1c4", socket_a1c4_);
    uart_->SaveState(w);
}

void CasioCassiopeiaEm500Modem::RestoreState(StateReader& r) {
    r.Read("ctrl_8600", ctrl_8600_);
    r.Read("socket_a1c0", socket_a1c0_);
    r.Read("socket_a1c4", socket_a1c4_);
    uart_->RestoreState(r);
}

void CasioCassiopeiaEm500Modem::PostRestore() {
    uart_->RepublishIrq();
}
