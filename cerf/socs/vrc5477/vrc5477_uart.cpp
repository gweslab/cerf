#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../cpu/vr5500/vr5500_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../tracing/kernel_debug_sink.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <string>

/* NEC VRC5477 northbridge dual 16550 UART (UART0 at base, UART1 at +0x40;
   8-bit registers at 8-byte stride). TX bytes route to KernelDebugSink. */

namespace {

constexpr uint32_t kUartBlockBase = 0x1FA04200u;  /* VRC5477 regs 0x1FA00000 + UART0 0x4200 */
constexpr uint32_t kUartBlockSize = 0x80u;        /* UART0 0x4200..0x423F + UART1 0x4240..0x427F */
constexpr uint32_t kUartStride    = 0x40u;        /* UART1 is UART0 + 0x40 */

/* 8-bit registers at 8-byte stride; index = uoff >> 3 (UART0 union order). */
constexpr uint32_t kRegRbrThrDll = 0;  /* RBR(r)/THR(w); DLL when LCR.DLAB */
constexpr uint32_t kRegIerDlm    = 1;  /* IER; DLM when LCR.DLAB */
constexpr uint32_t kRegIirFcr    = 2;  /* IIR(r)/FCR(w) */
constexpr uint32_t kRegLcr       = 3;
constexpr uint32_t kRegMcr       = 4;
constexpr uint32_t kRegLsr       = 5;  /* read-only */
constexpr uint32_t kRegMsr       = 6;  /* read-only */
constexpr uint32_t kRegScr       = 7;

constexpr uint8_t kLcrDlab  = 1u << 7;
constexpr uint8_t kLsrThre  = 1u << 5;
constexpr uint8_t kLsrTemt  = 1u << 6;
constexpr uint8_t kIirNoInt = 0x01u;   /* 16550 IIR bit0=1 => no interrupt pending */

struct UartRegs {
    uint8_t ier, fcr, lcr, mcr, scr, dll, dlm;
};

class Vrc5477Uart : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Vr5500;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kUartBlockBase; }
    uint32_t MmioSize() const override { return kUartBlockSize; }

    uint8_t ReadByte (uint32_t addr) override;
    void    WriteByte(uint32_t addr, uint8_t value) override;

    /* Only the register file is machine state; tx_line_ is a host-side console
       line accumulator rebuilt as the guest writes. */
    void SaveState(StateWriter& w) override {
        static_assert(StateVisitCoversAllBytes<UartRegs>(
                          [](UartRegs& u, StateFieldBytes& f) { VisitRegs(u, f); }),
                      "VisitRegs must name or skip every field of UartRegs");
        StateWriteField field(w);
        for (UartRegs& u : regs_) VisitRegs(u, field);
    }
    void RestoreState(StateReader& r) override {
        StateReadField field(r);
        for (UartRegs& u : regs_) VisitRegs(u, field);
    }

private:
    uint32_t Index(uint32_t addr, uint32_t* reg) const {
        const uint32_t off  = addr - MmioBase();
        const uint32_t uart = (off >= kUartStride) ? 1u : 0u;
        *reg = ((off - uart * kUartStride) >> 3) & 7u;
        return uart;
    }

    template <typename F>
    static constexpr void VisitRegs(UartRegs& u, F& field) {
        field("ier", u.ier);
        field("fcr", u.fcr);
        field("lcr", u.lcr);
        field("mcr", u.mcr);
        field("scr", u.scr);
        field("dll", u.dll);
        field("dlm", u.dlm);
    }

    UartRegs    regs_[2]   = {};
    std::string tx_line_[2];
};

uint8_t Vrc5477Uart::ReadByte(uint32_t addr) {
    uint32_t reg;
    const uint32_t u = Index(addr, &reg);
    const bool dlab = (regs_[u].lcr & kLcrDlab) != 0;
    switch (reg) {
        case kRegRbrThrDll: return dlab ? regs_[u].dll : 0u;  /* RBR: no input source */
        case kRegIerDlm:    return dlab ? regs_[u].dlm : regs_[u].ier;
        case kRegIirFcr:    return kIirNoInt;
        case kRegLcr:       return regs_[u].lcr;
        case kRegMcr:       return regs_[u].mcr;
        case kRegLsr:       return kLsrThre | kLsrTemt;       /* THRE set or the guest TX poll spins forever; RX empty (DR=0) */
        case kRegMsr:       return 0u;
        case kRegScr:       return regs_[u].scr;
        default:            return 0u;
    }
}

void Vrc5477Uart::WriteByte(uint32_t addr, uint8_t value) {
    uint32_t reg;
    const uint32_t u = Index(addr, &reg);
    const bool dlab = (regs_[u].lcr & kLcrDlab) != 0;
    switch (reg) {
        case kRegRbrThrDll:
            if (dlab) {
                regs_[u].dll = value;
            } else {                                          /* THR: transmit */
                const char* tag = u ? "UART1" : "UART0";
                emu_.Get<KernelDebugSink>().EmitChar(static_cast<char>(value),
                                                     tx_line_[u], tag, true);
            }
            break;
        case kRegIerDlm: if (dlab) regs_[u].dlm = value; else regs_[u].ier = value; break;
        case kRegIirFcr: regs_[u].fcr = value; break;
        case kRegLcr:    regs_[u].lcr = value; break;
        case kRegMcr:    regs_[u].mcr = value; break;
        case kRegLsr:    break;                               /* LSR read-only */
        case kRegMsr:    break;                               /* MSR read-only */
        case kRegScr:    regs_[u].scr = value; break;
        default:         break;
    }
}

}  /* namespace */

REGISTER_SERVICE(Vrc5477Uart);
