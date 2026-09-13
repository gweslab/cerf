#include "../../peripherals/uart16550/uart16550.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"

/* Intel 81341/81342 Developer's Manual 315037-002US, section 16;
   siemens_mp377_v1040 nk.exe, VA 0x80409FDC. */

namespace {

class Iop13xxUart : public Uart16550 {
public:
    explicit Iop13xxUart(CerfEmulator& emu) : Uart16550(emu, Config{}) {}

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::IOP13xx;
    }

    uint32_t MmioBase() const override { return 0xFFD82340u; }
    uint32_t MmioSize() const override { return 0x00000030u; }

protected:
    uint32_t RegStride() const override { return 4u; }
    const char* Name() const override { return "UART0"; }

    void SetInterruptLine(bool pending) override {
        if (!pending) return;
        HaltUnsupportedAccess("SetInterruptLine(pending=true)", MmioBase(), 0);
    }
};

} /* namespace */

REGISTER_SERVICE(Iop13xxUart);
