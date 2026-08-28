#include "../peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

/* ISA-MEM system bus: VR4121 UM Table 6-6 p173 and VR4111 UM Table 6-6 p166 both give
   0x1000 0000-0x13FF FFFF as "System bus memory space (ISA-MEM)". */
constexpr uint32_t kBase = 0x10000120u;
constexpr uint32_t kSize = 0x08u;

/* casio_toricomail_ce212 nk.exe sub_9F0B955C (send) / sub_9F0B94DC (get);
   casio_cassiopeia_e55 nk.exe 0x9E8170C0 (send) / 0x9E817040 (get). */
constexpr uint32_t kOffData  = 0x00u;   /* data out sh 0($a2); RX = lhu 0($a2) high byte */
constexpr uint32_t kOffCtrl  = 0x02u;   /* command/status 0x1100/0x9100/0x9900, 0x3330 init */
constexpr uint32_t kOffProbe = 0x04u;   /* loopback probe, writes 0x80/0 and reads bit 7 */

/* Init requires (status & 0x2320) == 0x2320; D1 (0x2) TX-ACK and D12 (0x1000) RX-ready
   are the peer-handshake bits both drivers poll. */
constexpr uint16_t kCtrlPresent = 0x2320u;

class CasioHostLink : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        if (!bd) return false;
        const auto b = bd->GetBoard();
        return b == Board::CasioToricomail || b == Board::CasioCassiopeiaE55;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint16_t ReadHalf(uint32_t addr) override {
        switch (addr - kBase) {
            case kOffCtrl:  return kCtrlPresent;
            case kOffProbe: return probe_;
            default: HaltUnsupportedAccess("CasioHostLink ReadHalf", addr, 0);
        }
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        switch (addr - kBase) {
            case kOffData:
                LOG(Board, "Casio host-link TX 0x%02X (no docked peer)\n", value & 0xFFu);
                return;
            case kOffCtrl:  return;
            case kOffProbe: probe_ = static_cast<uint16_t>(value & 0x80u); return;
            default: HaltUnsupportedAccess("CasioHostLink WriteHalf", addr, value);
        }
    }

    uint8_t  ReadByte (uint32_t addr) override { HaltUnsupportedAccess("CasioHostLink ReadByte", addr, 0); }
    uint32_t ReadWord (uint32_t addr) override { HaltUnsupportedAccess("CasioHostLink ReadWord", addr, 0); }
    void WriteByte(uint32_t addr, uint8_t  v) override { HaltUnsupportedAccess("CasioHostLink WriteByte", addr, v); }
    void WriteWord(uint32_t addr, uint32_t v) override { HaltUnsupportedAccess("CasioHostLink WriteWord", addr, v); }

    void SaveState(StateWriter& w) override { w.Write(probe_); }
    void RestoreState(StateReader& r) override { r.Read(probe_); }

private:
    uint16_t probe_ = 0u;
};

}

REGISTER_SERVICE(CasioHostLink);
