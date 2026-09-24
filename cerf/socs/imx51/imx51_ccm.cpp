#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <array>
#include <cstdint>

namespace {

/* i.MX51 CCM (Clock Controller Module), MCIMX51RM Ch.7 Table 7-3, base
   0x73FD4000, regs +0x0..0x80, R/W storage (no clock tree modelled). Resets
   are load-bearing - start() read-modify-writes CCGR6 (0x78)/CBCDR (0x14)/CBCMR
   (0x18); CDHIPR (0x44) reset 0 = handshake idle so divider polls pass. */
constexpr uint32_t kBase = 0x73FD4000u;
constexpr uint32_t kSize = 0x00001000u;

struct CcmReset { uint32_t off; uint32_t val; };
constexpr CcmReset kResets[] = {   /* Table 7-3 non-zero reset values */
    /* CCR (RM Fig 7-3: bits 11..9 = 1, oscnt = 0xFF) with cosc_en (bit12) = 1.
       cosc_en's reset is undefined in the RM, but SBOOT gates the 24 MHz DPLL
       reference on it (Bootloader.bin 0x8FF06678 `tst #0x1000`) and never sets it;
       read as 0 the reference is 0 → every PLL/EPIT clock is 0 → CE kernel aborts. */
    {0x00, 0x00001EFFu},  /* CCR    */
    {0x08, 0x00000010u},  /* CSR    */ {0x14, 0x19239145u},  /* CBCDR  */
    {0x18, 0x000020C0u},  /* CBCMR  */ {0x1C, 0xA6A2A020u},  /* CSCMR1 */
    {0x20, 0x02A5A88Au},  /* CSCMR2 */ {0x24, 0x00C30318u},  /* CSCDR1 */
    {0x28, 0x00860041u},  /* CS1CDR */ {0x2C, 0x00860041u},  /* CS2CDR */
    {0x30, 0x04320DD2u},  /* CDCDR  */ {0x34, 0x02090241u},  /* CSCDR2 */
    {0x38, 0x00010241u},  /* CSCDR3 */ {0x3C, 0x00010241u},  /* CSCDR4 */
    {0x48, 0x00000001u},  /* CDCR   */ {0x4C, 0x00000079u},  /* CLPCR  */
    {0x54, 0xFFFFFFFFu},  /* CIMR   */ {0x58, 0x000A0001u},  /* CCOSR  */
    {0x5C, 0x0000FE62u},  /* CGPR   */ {0x60, 0xFFFFFFFFu},  /* CCGR0  */
    {0x64, 0xFFFFFFFFu},  /* CCGR1  */ {0x68, 0xFFFFFFFFu},  /* CCGR2  */
    {0x6C, 0xFFFFFFFFu},  /* CCGR3  */ {0x70, 0xFFFFFFFFu},  /* CCGR4  */
    {0x74, 0xFFFFFFFFu},  /* CCGR5  */ {0x78, 0xFFFFFFFFu},  /* CCGR6  */
    {0x80, 0xFFFFFFFFu},  /* CMEOR  */
};

class Imx51Ccm : public Peripheral {
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

    /* JIT-thread-only register file (no worker thread). */
    void SaveState(StateWriter& w) override    { w.WriteBytes("regs", regs_.data(), sizeof(regs_)); }
    void RestoreState(StateReader& r) override { r.ReadBytes("regs", regs_.data(), sizeof(regs_)); }

private:
    std::array<uint32_t, kSize / 4> regs_{};
};

}  /* namespace */

REGISTER_SERVICE(Imx51Ccm);
