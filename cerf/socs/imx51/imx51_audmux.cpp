#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <array>
#include <cstdint>

namespace {

/* i.MX51 AUDMUX (Digital Audio Multiplexer), MCIMX51RM Ch (base 0x83FD0000,
   Table 2-1) - audio careful-stub (agent_docs/rules.md): the audio driver's
   AudMuxContext::MapRegisters (wavedev2_cs42448.dll sub_C0CB0D28) maps 0x3C
   bytes and writes the SSI<->port routing (PTCRn/PDCRn); pure config, no poll. */
constexpr uint32_t kBase = 0x83FD0000u;
constexpr uint32_t kSize = 0x00004000u;   /* AIPS slot, RM Table 2-1 */

struct AudmuxReset { uint32_t off; uint32_t val; };
/* Port Timing/Data Control reset values, MCIMX51RM AUDMUX register summary. */
constexpr AudmuxReset kResets[] = {
    {0x00, 0xAD400800u},  /* PTCR1 */ {0x04, 0x0000A000u},  /* PDCR1 */
    {0x08, 0xA5000800u},  /* PTCR2 */ {0x0C, 0x00008000u},  /* PDCR2 */
    {0x10, 0x9CC00800u},  /* PTCR3 */ {0x14, 0x00006000u},  /* PDCR3 */
    {0x18, 0x00000800u},  /* PTCR4 */ {0x1C, 0x00004000u},  /* PDCR4 */
    {0x20, 0x00000800u},  /* PTCR5 */ {0x24, 0x00002000u},  /* PDCR5 */
    {0x28, 0x00000800u},  /* PTCR6 */ {0x2C, 0x00000000u},  /* PDCR6 */
};

class Imx51Audmux : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override {
        for (const auto& r : kResets) regs_[r.off >> 2] = r.val;
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override { return regs_[(addr - kBase) >> 2]; }
    void WriteWord(uint32_t addr, uint32_t value) override {
        regs_[(addr - kBase) >> 2] = value;
    }

    void SaveState(StateWriter& w) override    { w.WriteBytes("regs", regs_.data(), sizeof(regs_)); }
    void RestoreState(StateReader& r) override { r.ReadBytes("regs", regs_.data(), sizeof(regs_)); }

private:
    std::array<uint32_t, kSize / 4> regs_{};
};

}  /* namespace */

REGISTER_SERVICE(Imx51Audmux);
