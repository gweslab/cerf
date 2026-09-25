#include "dynamic_rate_resampler.h"

#include <cmath>
#include <cstdint>
#include <cstring>
#include <limits>

namespace {

/* Hans-Kristian Arntzen, "Dynamic Rate Control for Retro Game Emulators"
   (2012), Table 2: d = 0.005. */
constexpr double   kMaxDeviation   = 0.005;
constexpr uint32_t kEstimateBlocks = 64;

}

void DynamicRateResampler::Restart() {
    pos_     = -1.0;
    std::memset(hist_, 0, sizeof(hist_));
    blocks_  = 0;
    started_ = false;
    ForgetLastSample();
}

void DynamicRateResampler::ForgetLastSample() {
    have_prev_ = false;
}

void DynamicRateResampler::DeviceStarted() {
    blocks_  = 0;
    started_ = true;
    ForgetLastSample();
}

bool DynamicRateResampler::CountBlock() {
    return started_ && ++blocks_ % kEstimateBlocks == 0;
}

void DynamicRateResampler::Sample(const DevicePosition& p) {
    if (have_prev_) {
        const bool same_run = p.valid && prev_.valid && p.epoch == prev_.epoch &&
                              p.unfed == prev_.unfed && p.rate_hz == prev_.rate_hz &&
                              p.rate_hz != 0u && p.wall_s > prev_.wall_s;
        if (same_run) {
            win_frames_[win_head_]  = static_cast<double>(p.samples - prev_.samples);
            win_nominal_[win_head_] = (p.wall_s - prev_.wall_s) * static_cast<double>(p.rate_hz);
            win_head_ = (win_head_ + 1u) % kWindows;
            if (win_count_ < kWindows) ++win_count_;
            double sum_frames = 0.0, sum_nominal = 0.0;
            for (uint32_t i = 0; i < win_count_; ++i) {
                sum_frames  += win_frames_[i];
                sum_nominal += win_nominal_[i];
            }
            if (sum_frames > 0.0) base_ = sum_frames / sum_nominal;
        }
        estimated_ = true;
    }
    prev_      = p;
    have_prev_ = true;
}

/* Olli Niemitalo, "Polynomial Interpolators for High-Quality Resampling of
   Oversampled Audio", p. 11: 4-point, 3rd-order Hermite impulse response. */
double DynamicRateResampler::Tap(double x) {
    const double a = std::fabs(x);
    if (a < 1.0) return 1.0 - 2.5 * a * a + 1.5 * a * a * a;
    if (a < 2.0) return 2.0 - 4.0 * a + 2.5 * a * a - 0.5 * a * a * a;
    return 0.0;
}

uint32_t DynamicRateResampler::Process(const int16_t* in, uint32_t in_frames,
                                       uint32_t channels, double fill_frames,
                                       double capacity_frames,
                                       int16_t* out, uint32_t out_cap_frames) {
    auto sample = [&](int64_t i, uint32_t c) -> double {
        if (i < 0) return hist_[3 + i][c];
        return in[static_cast<size_t>(i) * channels + c];
    };

    /* Arntzen, "Dynamic Rate Control for Retro Game Emulators", §2.3 eq. (2). */
    const double ratio = base_ * (1.0 + kMaxDeviation *
                                  (capacity_frames - 2.0 * fill_frames) / capacity_frames);
    const double step  = 1.0 / ratio;

    uint32_t produced = 0;
    for (;;) {
        const int64_t i = static_cast<int64_t>(std::floor(pos_));
        if (i + 2 > static_cast<int64_t>(in_frames) - 1) break;
        if (produced == out_cap_frames) return std::numeric_limits<uint32_t>::max();
        const double t = pos_ - static_cast<double>(i);
        const double w[4] = { Tap(t + 1.0), Tap(t), Tap(1.0 - t), Tap(2.0 - t) };
        for (uint32_t c = 0; c < channels; ++c) {
            double y = 0.0;
            for (int k = 0; k < 4; ++k) y += w[k] * sample(i - 1 + k, c);
            y = std::round(y);
            if (y > 32767.0)  y = 32767.0;
            if (y < -32768.0) y = -32768.0;
            out[static_cast<size_t>(produced) * channels + c] = static_cast<int16_t>(y);
        }
        ++produced;
        pos_ += step;
    }
    pos_ -= static_cast<double>(in_frames);

    int16_t next[3][kMaxChannels] = {};
    for (int j = 0; j < 3; ++j)
        for (uint32_t c = 0; c < channels; ++c)
            next[j][c] = static_cast<int16_t>(sample(static_cast<int64_t>(in_frames) - 3 + j, c));
    std::memcpy(hist_, next, sizeof(hist_));
    return produced;
}

bool DynamicRateResampler::TakeEstimate(double* ratio) {
    if (!estimated_) return false;
    estimated_ = false;
    *ratio     = base_;
    return true;
}
