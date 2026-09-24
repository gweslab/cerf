#define NOMINMAX

#include "siemens_mp377_touch_panel.h"
#include "../../peripherals/silicon_motion_sm501/siemens_mp377_sm501.h"

#include "../../boards/board_context.h"
#include "siemens_mp377_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../state/state_stream.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/irq_controller.h"

#include <cstdint>

namespace siemens_mp377 {

namespace {

struct TouchPoint {
    int32_t x;
    int32_t y;
};

struct TouchCalibrationProfile {
    SiemensMp377PanelProfile profile;
    TouchPoint raw_points[5];
};

struct TouchAffineInverse {
    double xx;
    double xy;
    double x0;
    double yx;
    double yy;
    double y0;
};

/* siemens_mp377_v1040 NK.bin file default.hv contains the three
   CalibrationData12in/15in/19in five-point raw ADC profiles below. */
static constexpr TouchCalibrationProfile kTouchCalibrationProfiles[] = {
    {SiemensMp377PanelProfile::Inch12_800x600, {{1855, 1859}, {3023, 3008}, {3034, 676}, {672, 672}, {677, 3011}}},
    {SiemensMp377PanelProfile::Inch15_1024x768, {{1879, 1844}, {3173, 3073}, {3175, 655}, {585, 654}, {586, 3035}}},
    {SiemensMp377PanelProfile::Inch19_1280x1024, {{1842, 1838}, {2937, 2976}, {2936, 717}, {697, 713}, {712, 2994}}},
};

const TouchCalibrationProfile& CurrentTouchCalibrationProfile() {
    for (const auto& profile : kTouchCalibrationProfiles) {
        if (profile.profile == kMp377HwiPanelProfile) return profile;
    }
    return kTouchCalibrationProfiles[0];
}

TouchPoint DisplayCalibrationPoint(const TouchCalibrationProfile& profile, uint32_t index) {
    const uint32_t panel_width = Mp377PanelWidth(profile.profile);
    const uint32_t panel_height = Mp377PanelHeight(profile.profile);
    const int32_t x_inset = static_cast<int32_t>(2u * (panel_width / 20u));
    const int32_t y_inset = static_cast<int32_t>(2u * (panel_height / 20u));
    const int32_t width = static_cast<int32_t>(panel_width);
    const int32_t height = static_cast<int32_t>(panel_height);

    switch (index) {
    case 1: return {x_inset, y_inset};
    case 2: return {x_inset, height - y_inset};
    case 3: return {width - x_inset, height - y_inset};
    case 4: return {width - x_inset, y_inset};
    default: return {width / 2, height / 2};
    }
}

bool Solve3x3(const double in_a[3][3], const double in_b[3], double out[3]) {
    double a[3][4] = {};
    for (int row = 0; row < 3; ++row) {
        for (int col = 0; col < 3; ++col)
            a[row][col] = in_a[row][col];
        a[row][3] = in_b[row];
    }

    for (int col = 0; col < 3; ++col) {
        int pivot = col;
        double pivot_abs = a[pivot][col] < 0.0 ? -a[pivot][col] : a[pivot][col];
        for (int row = col + 1; row < 3; ++row) {
            const double v = a[row][col] < 0.0 ? -a[row][col] : a[row][col];
            if (v > pivot_abs) {
                pivot_abs = v;
                pivot = row;
            }
        }
        if (pivot_abs < 1e-12) return false;
        if (pivot != col) {
            for (int i = col; i < 4; ++i) {
                const double tmp = a[col][i];
                a[col][i] = a[pivot][i];
                a[pivot][i] = tmp;
            }
        }

        const double div = a[col][col];
        for (int i = col; i < 4; ++i)
            a[col][i] /= div;

        for (int row = 0; row < 3; ++row) {
            if (row == col) continue;
            const double factor = a[row][col];
            for (int i = col; i < 4; ++i)
                a[row][i] -= factor * a[col][i];
        }
    }

    for (int i = 0; i < 3; ++i)
        out[i] = a[i][3];
    return true;
}

TouchAffineInverse BuildTouchAffineInverse(const TouchCalibrationProfile& profile) {
    double ata[3][3] = {};
    double atx[3] = {};
    double aty[3] = {};

    for (uint32_t i = 0; i < 5u; ++i) {
        const TouchPoint& raw = profile.raw_points[i];
        const TouchPoint display = DisplayCalibrationPoint(profile, i);
        const double r[3] = {static_cast<double>(raw.x), static_cast<double>(raw.y), 1.0};

        for (int row = 0; row < 3; ++row) {
            for (int col = 0; col < 3; ++col)
                ata[row][col] += r[row] * r[col];
            atx[row] += r[row] * static_cast<double>(display.x);
            aty[row] += r[row] * static_cast<double>(display.y);
        }
    }

    double x_coeff[3] = {};
    double y_coeff[3] = {};
    if (!Solve3x3(ata, atx, x_coeff) || !Solve3x3(ata, aty, y_coeff)) return {0.0, 0.0, 0.0, 0.0, 0.0, 0.0};

    const double a = x_coeff[0];
    const double b = x_coeff[1];
    const double c = x_coeff[2];
    const double d = y_coeff[0];
    const double e = y_coeff[1];
    const double f = y_coeff[2];
    const double det = a * e - b * d;
    if (det > -1e-12 && det < 1e-12) return {0.0, 0.0, 0.0, 0.0, 0.0, 0.0};

    return {
        e / det, -b / det, (b * f - e * c) / det, -d / det, a / det, (d * c - a * f) / det,
    };
}

uint16_t ClampAdc12(double value) {
    int32_t rounded = static_cast<int32_t>(value >= 0.0 ? value + 0.5 : value - 0.5);
    if (rounded < 1) rounded = 1;
    if (rounded > 4095) rounded = 4095;
    return static_cast<uint16_t>(rounded);
}

} // namespace

bool SiemensMp377TouchPanel::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::SiemensMp377;
}

void SiemensMp377TouchPanel::OnReady() {
    const TouchAffineInverse affine = BuildTouchAffineInverse(CurrentTouchCalibrationProfile());
    touch_affine_[0] = affine.xx;
    touch_affine_[1] = affine.xy;
    touch_affine_[2] = affine.x0;
    touch_affine_[3] = affine.yx;
    touch_affine_[4] = affine.yy;
    touch_affine_[5] = affine.y0;
    ResetTransport();
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        if (!emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) ResetTransport();
    });
}

void SiemensMp377TouchPanel::ResetTransport() {
    smi_last_cmd_.store(0u, std::memory_order_release);
    penirq_enabled_.store(0u, std::memory_order_release);
    touch_down_.store(0u, std::memory_order_release);
    touch_x_.store(0u, std::memory_order_release);
    touch_y_.store(0u, std::memory_order_release);
    for (auto& response : smi_response_q_) response = 0u;
    smi_response_head_ = 0u;
    smi_response_tail_ = 0u;
    emu_.Get<IrqController>().DeAssertIrq(kTouchIrqSource);
}

bool SiemensMp377TouchPanel::EffectiveTouchDown() const {
    return touch_down_.load(std::memory_order_acquire) != 0u;
}

bool SiemensMp377TouchPanel::QueueSmiCommand(uint16_t cmd) {
    /* SM501 Databook v1.02, SSP chapter: both transmit and receive FIFOs
       contain eight 16-bit entries.  An additional received frame sets the
       overrun condition and does not alter the receive FIFO. */
    const uint8_t control = static_cast<uint8_t>(cmd);
    switch (control) {
    case 0x00u:
    case 0x90u:
    case 0x93u:
    case 0xD0u:
    case 0xD3u:
    case 0xE0u:
        break;
    default:
        emu_.Get<Fatal>().Die("MP377 ADS7846 unsupported control byte 0x%02X", control);
    }

    const uint8_t previous_control = static_cast<uint8_t>(smi_last_cmd_.load(std::memory_order_relaxed));
    smi_last_cmd_.store(cmd, std::memory_order_relaxed);
    if (control != 0u) {
        penirq_enabled_.store((control & 1u) == 0u ? 1u : 0u, std::memory_order_release);
        RecomputePenIrq();
    }
    if (PendingSmiResponseCount() == 8u) return true;

    const uint32_t next = (smi_response_tail_ + 1u) & 15u;
    smi_response_q_[smi_response_tail_] = previous_control == 0u ? 0u : AdcResponseForControl(previous_control);
    smi_response_tail_ = next;
    return false;
}

uint16_t SiemensMp377TouchPanel::PopSmiResponse() {
    if (smi_response_head_ == smi_response_tail_) return 0u;
    const uint16_t response = smi_response_q_[smi_response_head_];
    smi_response_head_ = (smi_response_head_ + 1u) & 15u;
    return response;
}

bool SiemensMp377TouchPanel::HasPendingSmiResponse() const {
    return smi_response_head_ != smi_response_tail_;
}

uint32_t SiemensMp377TouchPanel::PendingSmiResponseCount() const {
    return (smi_response_tail_ - smi_response_head_) & 15u;
}

void SiemensMp377TouchPanel::HostPointToTouchRaw(uint32_t x, uint32_t y, uint16_t* raw_x, uint16_t* raw_y) const {
    /* siemens_mp377_v1040 touch.dll sub_29E2474. */
    const double dx = static_cast<double>(x);
    const double dy = static_cast<double>(y);
    *raw_x = ClampAdc12(touch_affine_[0] * dx + touch_affine_[1] * dy + touch_affine_[2]);
    *raw_y = ClampAdc12(touch_affine_[3] * dx + touch_affine_[4] * dy + touch_affine_[5]);
}

uint32_t SiemensMp377TouchPanel::ReadPenDetectReg() {
    /* siemens_mp377_v1040 touch.dll sub_29E2B3C, VA 0xFFD82484. */
    return EffectiveTouchDown() ? 0x00000000u : 0x00000008u;
}

uint16_t SiemensMp377TouchPanel::AdcResponseForControl(uint8_t control) const {
    if (!EffectiveTouchDown()) return 0u;

    const uint32_t x = touch_x_.load(std::memory_order_relaxed);
    const uint32_t y = touch_y_.load(std::memory_order_relaxed);

    uint16_t raw_x = 0;
    uint16_t raw_y = 0;
    HostPointToTouchRaw(x, y, &raw_x, &raw_y);

    switch (control) {
    /* siemens_mp377_v1040 touch.dll sub_29E23B0 reads and discards the
       response to control byte E0h. */
    case 0xE0u: return 0u;
    /* TI ADS7846 SBAS125H, tables II-V;
       siemens_mp377_v1040 touch.dll sub_29E27C0. */
    case 0xD0u:
    case 0xD3u: return raw_x;
    case 0x90u:
    case 0x93u: return raw_y;
    }
    emu_.Get<Fatal>().Die("MP377 ADS7846 invalid conversion state 0x%02X", control);
}

uint32_t SiemensMp377TouchPanel::ReadSmiSampleWord() {
    /* SM501 Databook v1.02, SSP Data; MP377 smibase.dll operation 2. */
    return static_cast<uint32_t>(PopSmiResponse());
}

void SiemensMp377TouchPanel::UpdateHostPointer(int x, int y, bool down) {
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    if (x >= static_cast<int>(kFbWidth)) x = static_cast<int>(kFbWidth) - 1;
    if (y >= static_cast<int>(kFbHeight)) y = static_cast<int>(kFbHeight) - 1;

    touch_x_.store(static_cast<uint32_t>(x), std::memory_order_relaxed);
    touch_y_.store(static_cast<uint32_t>(y), std::memory_order_relaxed);

    touch_down_.store(down ? 1u : 0u, std::memory_order_release);
    RecomputePenIrq();
}

void SiemensMp377TouchPanel::CaptureLost() {
    touch_down_.store(0u, std::memory_order_release);
    RecomputePenIrq();
}

void SiemensMp377TouchPanel::RecomputePenIrq() {
    /* TI ADS7846 SBAS125H, table V and PENIRQ Output. */
    auto& irq = emu_.Get<IrqController>();
    if (penirq_enabled_.load(std::memory_order_acquire) != 0u && EffectiveTouchDown())
        irq.AssertIrq(kTouchIrqSource);
    else
        irq.DeAssertIrq(kTouchIrqSource);
}

void SiemensMp377TouchPanel::SaveState(StateWriter& w) const {
    uint32_t v = smi_last_cmd_.load(std::memory_order_acquire);
    w.Write("smi_last_cmd", v);
    v = penirq_enabled_.load(std::memory_order_acquire);
    w.Write("penirq_enabled", v);
    w.WriteBytes("smi_response_q", smi_response_q_, sizeof(smi_response_q_));
    w.Write("smi_response_head", smi_response_head_);
    w.Write("smi_response_tail", smi_response_tail_);
}

void SiemensMp377TouchPanel::RestoreState(StateReader& r) {
    uint32_t v = 0;
    r.Read("smi_last_cmd", v);
    smi_last_cmd_.store(v, std::memory_order_release);
    r.Read("penirq_enabled", v);
    penirq_enabled_.store(v != 0u ? 1u : 0u, std::memory_order_release);
    touch_down_.store(0u, std::memory_order_release);
    touch_x_.store(0u, std::memory_order_release);
    touch_y_.store(0u, std::memory_order_release);
    r.ReadBytes("smi_response_q", smi_response_q_, sizeof(smi_response_q_));
    r.Read("smi_response_head", smi_response_head_);
    r.Read("smi_response_tail", smi_response_tail_);
    smi_response_head_ &= 15u;
    smi_response_tail_ &= 15u;
}

void SiemensMp377TouchPanel::PostRestore() {
    RecomputePenIrq();
}

REGISTER_SERVICE(SiemensMp377TouchPanel);

} // namespace siemens_mp377
