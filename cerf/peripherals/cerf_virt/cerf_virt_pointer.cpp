#include "cerf_virt_pointer.h"
#include "cerf_virt_pointer_regs.h"
#include "cerf_virt_addr_map.h"
#include "cerf_guest_liveness.h"

#include "../peripheral_dispatcher.h"
#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../host/host_canvas.h"
#include "../../host/pointer_input.h"
#include "../../state/state_stream.h"

REGISTER_SERVICE(CerfVirtPointer);

bool CerfVirtPointer::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

void CerfVirtPointer::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t CerfVirtPointer::MmioBase() const {
    return emu_.Get<BoardContext>().GuestAdditionsWindowBase() + CerfVirt::kPointerOffset;
}
uint32_t CerfVirtPointer::MmioSize() const { return CerfVirt::kPointerSize; }

uint32_t CerfVirtPointer::ReadWord(uint32_t addr) {
    switch (addr - MmioBase()) {
        case CerfVirt::kPtrX:           return x_.load();
        case CerfVirt::kPtrY:           return y_.load();
        case CerfVirt::kPtrButtons:     return buttons_.load();
        case CerfVirt::kPtrWheelAccum:  return wheel_.load();
        case CerfVirt::kPtrSeq:         return seq_.load();
        default:                        return 0u;
    }
}

void CerfVirtPointer::WriteWord(uint32_t, uint32_t) {}

void CerfVirtPointer::SaveState(StateWriter& w) {
    w.Write<uint32_t>(x_.load());
    w.Write<uint32_t>(y_.load());
    w.Write<uint32_t>(buttons_.load());
    w.Write<uint32_t>(wheel_.load());
    w.Write<uint32_t>(seq_.load());
}

void CerfVirtPointer::RestoreState(StateReader& r) {
    uint32_t v;
    r.Read(v); x_.store(v);
    r.Read(v); y_.store(v);
    r.Read(v); buttons_.store(v);
    r.Read(v); wheel_.store(v);
    r.Read(v); seq_.store(v);
}

void CerfVirtPointer::Bump() { seq_.fetch_add(1u); }

void CerfVirtPointer::SetPointer(uint32_t nx, uint32_t ny, uint32_t buttons) {
    x_.store(nx);
    y_.store(ny);
    buttons_.store(buttons);
    Bump();
}

void CerfVirtPointer::AddWheel(int delta) {
    wheel_.fetch_add((uint32_t)delta);
    Bump();
}

void CerfVirtPointer::ClearButtons() {
    buttons_.store(0u);
    Bump();
}

namespace {

class CerfVirtPointerInput : public PointerInput {
public:
    using PointerInput::PointerInput;

    bool ShouldRegister() override {
        return emu_.Get<DeviceConfig>().guest_additions;
    }

    void OnMove(int sx, int sy, uint32_t button_mask) override {
        uint32_t nx, ny;
        Normalize(sx, sy, nx, ny);
        emu_.Get<CerfVirtPointer>().SetPointer(nx, ny, button_mask);
    }

    void OnWheel(int sx, int sy, int delta) override {
        (void)sx; (void)sy;
        emu_.Get<CerfVirtPointer>().AddWheel(delta);
    }

    void OnCaptureLost() override {
        emu_.Get<CerfVirtPointer>().ClearButtons();
    }

    bool SourceReady() const override {
        return emu_.Get<CerfGuestLiveness>().IsAlive();
    }

private:
    void Normalize(int sx, int sy, uint32_t& nx, uint32_t& ny) {
        auto& hc = emu_.Get<HostCanvas>();
        int w = (int)hc.GuestSurfaceWidth();
        int h = (int)hc.GuestSurfaceHeight();
        if (sx < 0) sx = 0;
        if (sy < 0) sy = 0;
        if (w > 0 && sx > w - 1) sx = w - 1;
        if (h > 0 && sy > h - 1) sy = h - 1;
        nx = (w > 1) ? (uint32_t)((uint64_t)sx * 65535u / (uint32_t)(w - 1)) : 0u;
        ny = (h > 1) ? (uint32_t)((uint64_t)sy * 65535u / (uint32_t)(h - 1)) : 0u;
    }
};

REGISTER_SERVICE_AS(CerfVirtPointerInput, PointerInput);

}
