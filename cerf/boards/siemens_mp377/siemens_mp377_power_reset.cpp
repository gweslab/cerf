#include "siemens_mp377_power_reset.h"

#include "../../peripherals/peripheral_base.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/state_stream.h"
#include "../board_context.h"
#include "siemens_mp377_id.h"

#include <array>
#include <cstdint>

namespace {

class SiemensMp377PowerReset : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SiemensMp377;
    }

    void OnReady() override {
        Reset();
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) return;
            Reset();
        });
    }

    uint32_t MmioBase() const override { return siemens_mp377::kMp377PowerResetBase; }
    uint32_t MmioSize() const override {
        return siemens_mp377::kMp377PowerResetEnd - siemens_mp377::kMp377PowerResetBase;
    }

    uint8_t ReadByte(uint32_t addr) override { HaltUnsupportedAccess("MP377 power/reset byte read", addr, 0); }
    uint16_t ReadHalf(uint32_t addr) override { HaltUnsupportedAccess("MP377 power/reset halfword read", addr, 0); }
    uint32_t ReadWord(uint32_t addr) override {
        const int idx = KnownRegisterIndex(addr);
        if (idx >= 0) {
            const uint32_t value = regs_[static_cast<size_t>(idx)];
            return value;
        }
        HaltUnsupportedAccess("MP377 power/reset unknown word read", addr, 0);
    }

    void WriteByte(uint32_t addr, uint8_t value) override {
        HaltUnsupportedAccess("MP377 power/reset byte write", addr, value);
    }
    void WriteHalf(uint32_t addr, uint16_t value) override {
        HaltUnsupportedAccess("MP377 power/reset halfword write", addr, value);
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        const int idx = KnownRegisterIndex(addr);
        if (idx >= 0) {
            regs_[static_cast<size_t>(idx)] = value;
            return;
        }
        HaltUnsupportedAccess("MP377 power/reset unknown word write", addr, value);
    }

    void SaveState(StateWriter& w) override { w.WriteBytes("regs", regs_.data(), regs_.size() * sizeof(regs_[0])); }
    void RestoreState(StateReader& r) override { r.ReadBytes("regs", regs_.data(), regs_.size() * sizeof(regs_[0])); }

private:
    void Reset() { regs_.fill(0); }

    static int KnownRegisterIndex(uint32_t addr) {
        const uint32_t rel = addr - siemens_mp377::kMp377PowerResetBase;
        const uint32_t block = rel / siemens_mp377::kMp377PowerResetBlockBytes;
        const uint32_t off = rel % siemens_mp377::kMp377PowerResetBlockBytes;

        /* siemens_mp377_v1040 nk.exe OALIoCtlHalLaunch 0x80444FEC-0x80445070;
           PowerFail.dll IstPowerFail 0x02951804-0x0295187C. */
        if (block < 2u) {
            const uint32_t base = block * 8u;
            switch (off) {
            case 0x04u: return static_cast<int>(base + 0u);
            case 0x08u: return static_cast<int>(base + 1u);
            case 0x10u: return static_cast<int>(base + 2u);
            case 0x48u: return static_cast<int>(base + 3u);
            case 0x50u: return static_cast<int>(base + 4u);
            case 0x54u: return static_cast<int>(base + 5u);
            case 0x58u: return static_cast<int>(base + 6u);
            case 0x5Cu: return static_cast<int>(base + 7u);
            default: break;
            }
        } else if (block == 2u) {
            switch (off) {
            case 0x20u: return 16;
            case 0x64u: return 17;
            case 0x68u: return 18;
            case 0x70u: return 19;
            case 0x74u: return 20;
            default: break;
            }
        }
        return -1;
    }

    std::array<uint32_t, 21> regs_{};
};

} // namespace

REGISTER_SERVICE(SiemensMp377PowerReset);
