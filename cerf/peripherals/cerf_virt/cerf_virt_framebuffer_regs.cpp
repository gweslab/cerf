#include "cerf_virt_framebuffer.h"
#include "cerf_virt_addr_map.h"
#include "cerf_virt_customizations_reset.h"
#include "cerf_virt_fb_regs.h"

#include "../peripheral_base.h"
#include "../peripheral_dispatcher.h"
#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../host/refresh_rate_service.h"

namespace {

using CerfVirt::kFbRegWidth;
using CerfVirt::kFbRegHeight;
using CerfVirt::kFbRegBpp;
using CerfVirt::kFbRegStride;
using CerfVirt::kFbRegSizeBytes;
using CerfVirt::kFbRegMemBasePa;
using CerfVirt::kFbRegPresent;
using CerfVirt::kFbRegMemSizeTotal;
using CerfVirt::kFbRegPrimaryReserve;
using CerfVirt::kFbRegLogicalDpi;
using CerfVirt::kFbRegRefreshRate;
using CerfVirt::kFbRegSystemFontHeight;
using CerfVirt::kFbRegSystemFontPresent;
using CerfVirt::kFbRegCustomizationsApplied;

class CerfVirtFramebufferRegs : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<DeviceConfig>().guest_additions;
    }

    void OnReady() override {
        fb_ = &emu_.Get<CerfVirtFramebuffer>();
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override {
        return emu_.Get<BoardContext>().GuestAdditionsWindowBase()
             + CerfVirt::kFramebufferRegsOffset;
    }
    uint32_t MmioSize() const override { return CerfVirt::kFramebufferRegsSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        switch (off) {
            case kFbRegWidth:     return fb_->Width();
            case kFbRegHeight:    return fb_->Height();
            case kFbRegBpp:       return fb_->Bpp();
            case kFbRegStride:    return fb_->Stride();
            case kFbRegSizeBytes: return fb_->SizeBytes();
            case kFbRegMemBasePa: return fb_->MemBasePa();
            case kFbRegPresent:   return 0u;
            case kFbRegMemSizeTotal: return fb_->RegionBytes();
            case kFbRegPrimaryReserve: return fb_->PrimaryReserveBytes();
            case kFbRegLogicalDpi: return emu_.Get<DeviceConfig>().screen_dpi;
            case kFbRegRefreshRate:
                return (uint32_t)emu_.Get<RefreshRateService>().GetRefreshRate();
            case kFbRegSystemFontHeight:
                return (uint32_t)emu_.Get<DeviceConfig>().guest_additions_font_size;
            case kFbRegSystemFontPresent:
                return emu_.Get<DeviceConfig>().guest_additions_font_size_set ? 1u : 0u;
            default:              return 0u;
        }
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off == kFbRegPresent) { fb_->MarkDirty(); return; }
        if (off == kFbRegCustomizationsApplied) {
            emu_.Get<CerfVirtCustomizationsReset>().OnCustomizationsApplied();
            return;
        }
        LOG(Periph, "[CerfVirtFbRegs] write +0x%X = 0x%08X "
                    "(non-WO register; ignored)\n", off, value);
    }

private:
    CerfVirtFramebuffer* fb_ = nullptr;
};

REGISTER_SERVICE(CerfVirtFramebufferRegs);

}
