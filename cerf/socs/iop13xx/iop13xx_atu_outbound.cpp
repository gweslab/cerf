#include "iop13xx_atu_state.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

namespace {
constexpr uint32_t kAtuOutboundBase = 0xFFDCD300u;
constexpr uint32_t kAtuOutboundSize = 0x00000030u;

class Iop13xxAtuOutbound final : public Peripheral {
public:
    using Peripheral::Peripheral;
    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::IOP13xx;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }
    uint32_t MmioBase() const override { return kAtuOutboundBase; }
    uint32_t MmioSize() const override { return kAtuOutboundSize; }
    uint32_t ReadWord(uint32_t addr) override { return ReadRegister((addr & ~3u) - kAtuOutboundBase); }
    uint16_t ReadHalf(uint32_t addr) override {
        return static_cast<uint16_t>(ReadWord(addr & ~3u) >> ((addr & 2u) * 8u));
    }
    uint8_t ReadByte(uint32_t addr) override {
        return static_cast<uint8_t>(ReadWord(addr & ~3u) >> ((addr & 3u) * 8u));
    }
    void WriteWord(uint32_t addr, uint32_t value) override { WriteRegister((addr & ~3u) - kAtuOutboundBase, value); }
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
    void SaveState(StateWriter& writer) override { emu_.Get<Iop13xxAtuState>().SaveOutboundState(writer); }
    void RestoreState(StateReader& reader) override { emu_.Get<Iop13xxAtuState>().RestoreOutboundState(reader); }

private:
    uint32_t ReadRegister(uint32_t offset) const {
        const auto& atu = emu_.Get<Iop13xxAtuState>();
        if (offset == 0x00u) return atu.Oiobar();
        if (offset == 0x04u) return atu.Oiowtvr();
        if (offset >= 0x08u && offset < 0x28u) {
            const uint32_t relative = offset - 0x08u;
            const auto& window = atu.Oum(relative / 0x08u);
            return (relative & 0x04u) ? window.wtvr : window.bar;
        }
        HaltUnsupportedAccess("IOP13xx ATU outbound register read", kAtuOutboundBase + offset, 0);
    }
    void WriteRegister(uint32_t offset, uint32_t value) {
        auto& atu = emu_.Get<Iop13xxAtuState>();
        if (offset == 0x00u) {
            atu.SetOiobar(value);
            return;
        }
        if (offset == 0x04u) {
            atu.SetOiowtvr(value);
            return;
        }
        if (offset >= 0x08u && offset < 0x28u) {
            const uint32_t relative = offset - 0x08u;
            const uint32_t index = relative / 0x08u;
            if (relative & 0x04u)
                atu.SetOumwtvr(index, value);
            else
                atu.SetOumbar(index, value);
            return;
        }
        HaltUnsupportedAccess("IOP13xx ATU outbound register write", kAtuOutboundBase + offset, value);
    }
};

REGISTER_SERVICE(Iop13xxAtuOutbound);
} // namespace
