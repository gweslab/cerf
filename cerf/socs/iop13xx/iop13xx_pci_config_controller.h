#pragma once

#include "iop13xx_pci_config.h"
#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

template <uint32_t kBase, bool kPrimary> class Iop13xxPciConfigController : public Peripheral {
public:
    using Peripheral::Peripheral;
    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::IOP13xx;
    }
    void OnReady() override {
        occar_ = 0u;
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            if (!emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) occar_ = 0u;
        });
    }
    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return 8u; }
    uint32_t ReadWord(uint32_t addr) override {
        switch (addr - kBase) {
        case 0u: return occar_;
        case 4u: {
            auto& config = emu_.Get<Iop13xxPciConfig>();
            return kPrimary ? config.ReadPrimary(occar_) : config.ReadSecondary(occar_);
        }
        default:
            HaltUnsupportedAccess(kPrimary ? "IOP13xx primary PCI config read" : "IOP13xx secondary PCI config read",
                                  addr, 0);
        }
    }
    uint16_t ReadHalf(uint32_t addr) override {
        return static_cast<uint16_t>(ReadWord(addr & ~3u) >> ((addr & 2u) * 8u));
    }
    uint8_t ReadByte(uint32_t addr) override {
        return static_cast<uint8_t>(ReadWord(addr & ~3u) >> ((addr & 3u) * 8u));
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        switch (addr - kBase) {
        case 0u: occar_ = value; return;
        case 4u:
            if constexpr (kPrimary) {
                if (!emu_.Get<Iop13xxPciConfig>().WritePrimary(occar_, value))
                    HaltUnsupportedAccess("SM501 PCI config register write", addr, value);
            } else {
                if (!emu_.Get<Iop13xxPciConfig>().WriteSecondary(occar_, value))
                    HaltUnsupportedAccess("SM501 PCI config register write", addr, value);
            }
            return;
        default:
            HaltUnsupportedAccess(kPrimary ? "IOP13xx primary PCI config write" : "IOP13xx secondary PCI config write",
                                  addr, value);
        }
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        if constexpr (kPrimary)
            HaltUnsupportedAccess("IOP13xx primary PCI config halfword write", addr, value);
        else
            MergeWrite(addr, value, 2u);
    }
    void WriteByte(uint32_t addr, uint8_t value) override {
        if constexpr (kPrimary)
            HaltUnsupportedAccess("IOP13xx primary PCI config byte write", addr, value);
        else
            MergeWrite(addr, value, 1u);
    }
    void SaveState(StateWriter& writer) override {
        writer.Write(occar_);
        if constexpr (kPrimary) emu_.Get<Iop13xxPciConfig>().SaveState(writer);
    }
    void RestoreState(StateReader& reader) override {
        reader.Read(occar_);
        if constexpr (kPrimary) emu_.Get<Iop13xxPciConfig>().RestoreState(reader);
    }


private:
    void MergeWrite(uint32_t addr, uint32_t value, uint32_t width) {
        const uint32_t aligned = addr & ~3u;
        const uint32_t shift = (addr & 3u) * 8u;
        const uint32_t mask = (width == 1u ? 0xFFu : 0xFFFFu) << shift;
        WriteWord(aligned, (ReadWord(aligned) & ~mask) | (value << shift));
    }
    uint32_t occar_ = 0u;
};
