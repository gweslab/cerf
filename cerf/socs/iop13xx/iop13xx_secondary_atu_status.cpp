#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "iop13xx_atu_state.h"
namespace {
class Iop13xxSecondaryAtuStatus final : public Peripheral {
public:
    using Peripheral::Peripheral;
    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::IOP13xx;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }
    uint32_t MmioBase() const override { return 0xFFDC8000u; }
    uint32_t MmioSize() const override { return 0x10u; }
    uint32_t ReadWord(uint32_t addr) override {
        HaltUnsupportedAccess("IOP13xx secondary ATU status word read", addr, 0);
    }
    uint16_t ReadHalf(uint32_t addr) override {
        /* Intel 81341/81342 Developer's Manual 315037-002US, tables 28,
           665 and 667. */
        if (addr - MmioBase() == kPciStatusOffset)
            return emu_.Get<Iop13xxAtuState>().Atusr();
        HaltUnsupportedAccess("IOP13xx secondary ATU status halfword read", addr, 0);
    }
    uint8_t ReadByte(uint32_t addr) override {
        HaltUnsupportedAccess("IOP13xx secondary ATU status byte read", addr, 0);
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        HaltUnsupportedAccess("IOP13xx secondary ATU status word write", addr, value);
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        HaltUnsupportedAccess("IOP13xx secondary ATU status halfword write", addr, value);
    }
    void WriteByte(uint32_t addr, uint8_t value) override {
        HaltUnsupportedAccess("IOP13xx secondary ATU status byte write", addr, value);
    }

private:
    static constexpr uint32_t kPciStatusOffset = 0x06u;
};
} // namespace
REGISTER_SERVICE(Iop13xxSecondaryAtuStatus);
