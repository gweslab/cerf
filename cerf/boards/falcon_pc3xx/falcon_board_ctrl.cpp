#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../socs/pxa255/pxa255_gpio.h"

#include <cstdint>

namespace {

/* Falcon PC3xx (Askey PC320/PC331) board-strap, CS0 PA 0x00001000, 16-bit
   (OAL nk.exe sub_800F3FFC reads +0x00 → board variant). 0 is an unverified
   default — the Falcon's physical strap is in no on-disk reference. */
class FalconBoardCtrl : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::FalconPC3xx;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        /* PCMCIA card-detect nCD is active-low (pcmcia.dll CardGetStatus reads
           GPIO10 low = card present); idle high = empty slot. Without this the
           bus-enum identifies a phantom card and deadlocks device.exe on the
           unknown-card SYSTEM/GweApiSetReady wait (GWES launches behind it). */
        emu_.Get<Pxa255Gpio>().SetInputLevel(10u, true);
    }

    uint32_t MmioBase() const override { return 0x00001000u; }
    uint32_t MmioSize() const override { return 0x00000100u; }

    uint16_t ReadHalf (uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;

private:
    static constexpr uint32_t kStrap = 0x00u;  /* board-variant strap (read-only). */
    uint16_t regs_[0x80u] = {};
};

uint16_t FalconBoardCtrl::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off == kStrap) return 0u;             /* variant-0 strap default. */
    if (off < sizeof(regs_) / 2u && (off & 1u) == 0u) return regs_[off / 2u];
    HaltUnsupportedAccess("ReadHalf", addr, 0);
}

void FalconBoardCtrl::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - MmioBase();
    if (off < sizeof(regs_) / 2u && (off & 1u) == 0u) { regs_[off / 2u] = value; return; }
    HaltUnsupportedAccess("WriteHalf", addr, value);
}

}  /* namespace */

REGISTER_SERVICE(FalconBoardCtrl);
