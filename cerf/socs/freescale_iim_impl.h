#pragma once

#include "../peripherals/peripheral_base.h"

#include "../boards/board_context.h"
#include "../core/cerf_emulator.h"
#include "../peripherals/peripheral_dispatcher.h"
#include "freescale_module_clocks.h"

#include <cstdint>
#include <optional>

/* Shared core for the Freescale IIM e-fuse box, same IP on i.MX31/i.MX51
   (MCIMX51RM Ch 41). An unblown e-fuse reads 0, so a virtual unprovisioned chip
   reads 0 across its whole fuse shadow. Each concrete owns its base, served
   ID/control registers, and fuse-shadow region(s). */
namespace cerf_freescale_iim_detail {

constexpr uint32_t kSize = 0x00004000u;  /* AIPS 16 KB peripheral slot */

template <uint32_t Base, const std::string_view& Soc>
class FreescaleIimBase : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == Soc;
    }
    void OnReady() override {
        module_clocks_ = &emu_.Get<FreescaleModuleClocks>();
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return Base; }
    uint32_t MmioSize() const override { return kSize; }

    /* The IIM is 8-bit registers on 32-bit boundaries; the guest reads them with
       any width, so route every width through one offset decoder. */
    uint8_t  ReadByte(uint32_t addr) override { return static_cast<uint8_t>(Read(addr - Base)); }
    uint16_t ReadHalf(uint32_t addr) override { return static_cast<uint16_t>(Read(addr - Base)); }
    uint32_t ReadWord(uint32_t addr) override { return Read(addr - Base); }

protected:
    /* Served ID/control-register value at `off`, or nullopt to fall through to
       the fuse-shadow / halt path. */
    virtual std::optional<uint32_t> ReadRegister(uint32_t off) const = 0;
    /* True when `off` lies in a fuse-bank shadow region (an unblown e-fuse on a
       virtual, unprovisioned chip reads 0). */
    virtual bool IsFuseShadow(uint32_t off) const = 0;

private:
    uint32_t Read(uint32_t off) {
        if (auto v = ReadRegister(off)) return *v;
        if (IsFuseShadow(off)) {
            module_clocks_->RequireRunning(FreescaleModule::kIim, "reads its fuse shadow");
            return 0;
        }
        HaltUnsupportedAccess("Read", Base + off, 0);
    }

    FreescaleModuleClocks* module_clocks_ = nullptr;
};

}  /* namespace cerf_freescale_iim_detail */
