#include "cerf_virt_cursor.h"
#include "cerf_virt_cursor_regs.h"
#include "cerf_virt_addr_map.h"

#include "../peripheral_dispatcher.h"
#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../jit/guest_engine.h"
#include "../../state/state_stream.h"

#include <cstring>

REGISTER_SERVICE(CerfVirtCursor);

bool CerfVirtCursor::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

void CerfVirtCursor::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
    const uint32_t pa = emu_.Get<BoardContext>().GuestAdditionsWindowBase() +
                        CerfVirt::kCurStageOffset;
    EmulatedMemory& mem = emu_.Get<EmulatedMemory>();
    mem.AddRegion(pa, CerfVirt::kCurStageSize, PAGE_READWRITE);
    stage_ = mem.TryTranslate(pa);
    if (!stage_) {
        LOG(Cerf, "[CerfVirtCursor] stage region at PA 0x%08X is not backed\n", pa);
        CerfFatalExit();
    }
    emu_.Get<GuestEngine>().SetDmaRegion(pa, CerfVirt::kCurStageSize);
}

uint32_t CerfVirtCursor::MmioBase() const {
    return emu_.Get<BoardContext>().GuestAdditionsWindowBase() + CerfVirt::kCursorOffset;
}
uint32_t CerfVirtCursor::MmioSize() const { return CerfVirt::kCursorSize; }

uint32_t CerfVirtCursor::ReadWord(uint32_t) {
    return 0u;
}

void CerfVirtCursor::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    (void)value;
    if (off != CerfVirt::kCurKick) return;

    const CerfVirt::CerfCursorDescriptor& d =
        *reinterpret_cast<const CerfVirt::CerfCursorDescriptor*>(stage_);

    GuestCursorShape s;
    s.visible = d.visible != 0;
    s.cx = d.cx; s.cy = d.cy; s.xhot = d.xhot; s.yhot = d.yhot; s.stride = d.stride;
    if (s.visible) {
        const uint32_t need = d.stride * d.cy * 2u;
        if (d.cy > CerfVirt::kCursorMaxDim || d.stride > CerfVirt::kCursorMaxStride ||
            need > CerfVirt::kCursorBitsBytes || need == 0u) {
            LOG(Periph, "[CerfVirtCursor] cursor %ux%u stride %u rejected\n",
                d.cx, d.cy, d.stride);
            return;
        }
        s.bits.assign(d.bits, d.bits + need);
    }

    {
        std::lock_guard<std::mutex> lk(shape_mutex_);
        shape_ = std::move(s);
        has_shape_ = true;
    }
    seq_.fetch_add(1u);
}

void CerfVirtCursor::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(shape_mutex_);
    w.Write<uint32_t>("seq", seq_.load());
    w.Write<uint8_t>("has_shape", has_shape_ ? 1u : 0u);
    static_assert(StateVisitCoversAllBytes<GuestCursorShape>(
                      [](GuestCursorShape& s, StateFieldBytes& f) { GuestCursorShape::Visit(s, f); }),
                  "GuestCursorShape::Visit must name or skip every field of GuestCursorShape");
    StateWriteField field(w);
    GuestCursorShape::Visit(shape_, field);
    w.Write<uint64_t>("shape_count", shape_.bits.size());
    w.WriteBytes("shape", shape_.bits.data(), shape_.bits.size());
}

void CerfVirtCursor::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(shape_mutex_);
    uint32_t v;
    r.Read("seq", v); seq_.store(v);
    uint8_t b;
    r.Read("has_shape", b); has_shape_ = (b != 0);
    StateReadField field(r);
    GuestCursorShape::Visit(shape_, field);
    uint64_t n = 0;
    r.Read("shape_count", n);
    shape_.bits.resize(static_cast<size_t>(n));
    r.ReadBytes("shape", shape_.bits.data(), static_cast<size_t>(n));
}

bool CerfVirtCursor::GetShape(GuestCursorShape& out) {
    std::lock_guard<std::mutex> lk(shape_mutex_);
    if (!has_shape_) return false;
    out = shape_;
    return true;
}
