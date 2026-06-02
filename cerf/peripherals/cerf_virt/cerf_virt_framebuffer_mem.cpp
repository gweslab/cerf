#include "cerf_virt_framebuffer.h"
#include "cerf_virt_addr_map.h"

#include "../peripheral_base.h"
#include "../peripheral_dispatcher.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"

#include <cstring>

namespace {

class CerfVirtFramebufferMem : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<DeviceConfig>().guest_additions;
    }

    void OnReady() override {
        fb_ = &emu_.Get<CerfVirtFramebuffer>();
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return CerfVirt::kFramebufferMemBase; }
    uint32_t MmioSize() const override { return fb_->RegionBytes(); }

    FastReadFn  FastReader() override { return &FastReadThunk;  }
    FastWriteFn FastWriter() override { return &FastWriteThunk; }

private:
    static uint32_t FastReadThunk(void* ctx, uint32_t off, uint32_t width_bytes) {
        auto* self = static_cast<CerfVirtFramebufferMem*>(ctx);
        const uint8_t* p = self->fb_->Bytes() + off;
        uint32_t v = 0;
        std::memcpy(&v, p, width_bytes);
        return v;
    }

    static void FastWriteThunk(void* ctx, uint32_t off,
                               uint32_t value, uint32_t width_bytes) {
        auto* self = static_cast<CerfVirtFramebufferMem*>(ctx);
        uint8_t* p = self->fb_->Bytes() + off;
        std::memcpy(p, &value, width_bytes);
        self->fb_->MarkDirty();
    }

    CerfVirtFramebuffer* fb_ = nullptr;
};

REGISTER_SERVICE(CerfVirtFramebufferMem);

}  /* namespace */
