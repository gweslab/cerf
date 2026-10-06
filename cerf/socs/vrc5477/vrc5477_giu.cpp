#include "vrc5477_giu.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../cpu/vr5500/vr5500_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "vrc5477_intc.h"

namespace {

/* Linux ddb5477.h: DDB_GIUFUNSEL at 0x4040 of the VRC5477 register window,
   VRC5477_IRQ_GPIO is controller source 26. */
constexpr uint32_t kBase         = 0x1FA04000u;
constexpr uint32_t kSize         = 0x00000200u;
constexpr uint32_t kOffIntClear  = 0x10u;
constexpr uint32_t kClearAll     = 0xFFFFFFFFu;
constexpr uint32_t kIntcSourceId = 26u;

}

REGISTER_SERVICE(Vrc5477Giu);

bool Vrc5477Giu::ShouldRegister() {
    return emu_.Get<BoardContext>().GetSocId() == SocId::Vr5500;
}

void Vrc5477Giu::OnReady() {
    intc_ = &emu_.Get<Vrc5477Intc>();
    GuestCpuReset& reset = emu_.Get<GuestCpuReset>();
    reset.RegisterResetListener([this](ResetLineKind) { latched_ = false; });
    reset.RegisterResetReleaseListener([this] { DriveSource(); });
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t Vrc5477Giu::MmioBase() const { return kBase; }
uint32_t Vrc5477Giu::MmioSize() const { return kSize; }

void Vrc5477Giu::WriteWord(uint32_t addr, uint32_t value) {
    if (addr - kBase != kOffIntClear || value != kClearAll) {
        HaltUnsupportedAccess("WriteWord", addr, value);
    }
    latched_ = false;
    DriveSource();
}

void Vrc5477Giu::DriveInterruptInput(bool active) {
    if (active && !input_) latched_ = true;
    input_ = active;
    DriveSource();
}

void Vrc5477Giu::DriveSource() {
    if (latched_ == line_) return;
    line_ = latched_;
    if (line_) intc_->AssertSource(kIntcSourceId);
    else       intc_->DeassertSource(kIntcSourceId);
}

void Vrc5477Giu::SaveState(StateWriter& w) {
    w.Write("giu_input", input_);
    w.Write("giu_latched", latched_);
    w.Write("giu_line", line_);
}

void Vrc5477Giu::RestoreState(StateReader& r) {
    r.Read("giu_input", input_);
    r.Read("giu_latched", latched_);
    r.Read("giu_line", line_);
}

void Vrc5477Giu::PostRestore() {
    if (line_) intc_->AssertSource(kIntcSourceId);
    else       intc_->DeassertSource(kIntcSourceId);
}
