#include "iop13xx_atu_state.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace {

constexpr uint32_t kAtuCoreBase = 0xFFDCD000u;
constexpr uint32_t kAtuCoreSize = 0x00000100u;
class Iop13xxAtuCore final : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::IOP13xx;
    }

    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kAtuCoreBase; }
    uint32_t MmioSize() const override { return kAtuCoreSize; }

    uint32_t ReadWord(uint32_t addr) override { return ReadRegister((addr & ~3u) - kAtuCoreBase); }

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t word = ReadWord(addr & ~3u);
        return static_cast<uint16_t>(word >> ((addr & 2u) * 8u));
    }

    uint8_t ReadByte(uint32_t addr) override {
        const uint32_t word = ReadWord(addr & ~3u);
        return static_cast<uint8_t>(word >> ((addr & 3u) * 8u));
    }

    void WriteWord(uint32_t addr, uint32_t value) override { WriteRegister((addr & ~3u) - kAtuCoreBase, value); }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t aligned = addr & ~3u;
        const uint32_t shift = (addr & 2u) * 8u;
        const uint32_t mask = 0xFFFFu << shift;
        WriteWord(aligned, (ReadWord(aligned) & ~mask) | (static_cast<uint32_t>(value) << shift));
    }

    void WriteByte(uint32_t addr, uint8_t value) override {
        const uint32_t aligned = addr & ~3u;
        const uint32_t shift = (addr & 3u) * 8u;
        const uint32_t mask = 0xFFu << shift;
        WriteWord(aligned, (ReadWord(aligned) & ~mask) | (static_cast<uint32_t>(value) << shift));
    }

    void SaveState(StateWriter& writer) override { emu_.Get<Iop13xxAtuState>().SaveCoreState(writer); }

    void RestoreState(StateReader& reader) override { emu_.Get<Iop13xxAtuState>().RestoreCoreState(reader); }

private:
    uint32_t ReadRegister(uint32_t offset) const {
        const auto& atu = emu_.Get<Iop13xxAtuState>();
        switch (offset) {
        case 0x00u:
        case 0x08u:
        case 0x0Cu: return 0;
        case 0x04u: return (static_cast<uint32_t>(atu.Atusr()) << 16) | atu.Atucmd();
        case 0x70u: return atu.Atucr();
        case 0x78u: return atu.Atuisr();
        case 0x7Cu: return atu.Atuimr();
        default: HaltUnsupportedAccess("IOP13xx ATU core register read", kAtuCoreBase + offset, 0);
        }
    }

    void WriteRegister(uint32_t offset, uint32_t value) {
        auto& atu = emu_.Get<Iop13xxAtuState>();
        switch (offset) {
        case 0x00u:
        case 0x08u:
        case 0x0Cu: return;
        case 0x04u:
            atu.SetAtucmd(static_cast<uint16_t>(value & 0xFFFFu));
            atu.ClearAtusrBits(static_cast<uint16_t>(value >> 16));
            return;
        case 0x70u: atu.SetAtucr(value); return;
        case 0x78u: atu.ClearAtuisrBits(value); return;
        case 0x7Cu: atu.SetAtuimr(value); return;
        default: HaltUnsupportedAccess("IOP13xx ATU core register write", kAtuCoreBase + offset, value);
        }
    }
};

REGISTER_SERVICE(Iop13xxAtuCore);

} // namespace
