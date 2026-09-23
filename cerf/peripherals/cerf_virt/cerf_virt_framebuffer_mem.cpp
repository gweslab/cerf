#include "cerf_virt_framebuffer.h"
#include "cerf_virt_addr_map.h"

#include "../peripheral_base.h"
#include "../peripheral_dispatcher.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"

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

    uint32_t MmioBase() const override { return fb_->MemBasePa(); }
    uint32_t MmioSize() const override { return fb_->RegionBytes(); }

    FastReadFn  FastReader() override { return &FastReadThunk;  }
    FastWriteFn FastWriter() override { return &FastWriteThunk; }

    void SaveState(StateWriter& w) override { fb_->SaveState(w); }
    void RestoreState(StateReader& r) override { fb_->RestoreState(r); }

private:
    static uint32_t FastReadThunk(void* ctx, uint32_t off, uint32_t width_bytes) {
        auto* self = static_cast<CerfVirtFramebufferMem*>(ctx);
        return static_cast<uint32_t>(cerf::le::UN(self->fb_->Bytes() + off, width_bytes));
    }

    static void FastWriteThunk(void* ctx, uint32_t off,
                               uint32_t value, uint32_t width_bytes) {
        auto* self = static_cast<CerfVirtFramebufferMem*>(ctx);
        cerf::le::PutN(self->fb_->Bytes() + off, value, width_bytes);
        self->fb_->MarkDirty();
    }

    CerfVirtFramebuffer* fb_ = nullptr;
};

REGISTER_SERVICE(CerfVirtFramebufferMem);

}
