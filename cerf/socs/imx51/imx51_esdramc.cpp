#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <array>
#include <cstdint>

namespace {

/* i.MX51 Enhanced SDRAM Controller (ESDRAMC), MCIMX51RM Rev.1 Ch.30, register
   base 0x83FD9000. The DDR timing/delay/mode registers have no effect in CERF
   (guest DRAM is already host-backed), so they are pure R/W storage - except
   the ESDSCR config handshake below. */
constexpr uint32_t kBase = 0x83FD9000u;
constexpr uint32_t kSize = 0x00001000u;

constexpr uint32_t kEsdscrOff = 0x14u;       /* ESDSCR, 0x83FD9014 (Table 30-4) */
constexpr uint32_t kConReq    = 1u << 15;    /* ESDSCR[15] CON_REQ, R/W */
constexpr uint32_t kConAck    = 1u << 14;    /* ESDSCR[14] CON_ACK, RO  */

class Imx51Esdramc : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        uint32_t v = regs_[off >> 2];
        if (off == kEsdscrOff) {
            /* ESDSCR[14] CON_ACK (RO, Table 30-6): the controller acks the
               config-access request once idle with no AXI pending. CERF issues
               no DDR AXI traffic, so it is always idle and acks immediately,
               i.e. CON_ACK tracks CON_REQ - the OAL polls (CON_REQ & CON_ACK). */
            v = (v & ~kConAck) | ((v & kConReq) ? kConAck : 0u);
        }
        return v;
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - kBase;
        regs_[off >> 2] = (off == kEsdscrOff) ? (value & ~kConAck) : value;
    }

    /* JIT-thread-only register file (no worker thread). */
    void SaveState(StateWriter& w) override    { w.WriteBytes("regs", regs_.data(), sizeof(regs_)); }
    void RestoreState(StateReader& r) override { r.ReadBytes("regs", regs_.data(), sizeof(regs_)); }

private:
    std::array<uint32_t, kSize / 4> regs_{};
};

}  /* namespace */

REGISTER_SERVICE(Imx51Esdramc);
