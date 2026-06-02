#include "cerf_virt_framebuffer.h"
#include "cerf_virt_addr_map.h"
#include "cerf_virt_fb_regs.h"

#include "../peripheral_base.h"
#include "../peripheral_dispatcher.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"

namespace {

using CerfVirt::kFbRegWidth;
using CerfVirt::kFbRegHeight;
using CerfVirt::kFbRegBpp;
using CerfVirt::kFbRegStride;
using CerfVirt::kFbRegSizeBytes;
using CerfVirt::kFbRegMemBasePa;
using CerfVirt::kFbRegPresent;
using CerfVirt::kFbRegMemSizeTotal;

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

    uint32_t MmioBase() const override { return CerfVirt::kFramebufferRegsBase; }
    uint32_t MmioSize() const override { return CerfVirt::kFramebufferRegsSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        switch (off) {
            case kFbRegWidth:     return fb_->Width();
            case kFbRegHeight:    return fb_->Height();
            case kFbRegBpp:       return fb_->Bpp();
            case kFbRegStride:    return fb_->Stride();
            case kFbRegSizeBytes: return fb_->SizeBytes();
            case kFbRegMemBasePa: return CerfVirt::kFramebufferMemBase;
            case kFbRegPresent:   return 0u;
            case kFbRegMemSizeTotal: return fb_->RegionBytes();
            default:              return 0u;
        }
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off == kFbRegPresent) { fb_->MarkDirty(); return; }
        LOG(Periph, "[CerfVirtFbRegs] write +0x%X = 0x%08X "
                    "(non-WO register; ignored)\n", off, value);
    }

private:
    CerfVirtFramebuffer* fb_ = nullptr;
};

REGISTER_SERVICE(CerfVirtFramebufferRegs);

}  /* namespace */
