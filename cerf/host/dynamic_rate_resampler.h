#pragma once

#include <cstdint>

struct DevicePosition {
    bool     valid   = false;
    uint32_t samples = 0;
    double   wall_s  = 0.0;
    uint32_t epoch   = 0;
    uint32_t unfed   = 0;
    uint32_t rate_hz = 0;
};

class DynamicRateResampler {
public:
    static constexpr uint32_t kMaxChannels = 2;

    void     Restart();
    void     DeviceStarted();
    bool     CountBlock();
    void     Sample(const DevicePosition& position);
    uint32_t Process(const int16_t* in, uint32_t in_frames, uint32_t channels,
                     double fill_frames, double capacity_frames,
                     int16_t* out, uint32_t out_cap_frames);
    bool     TakeEstimate(double* ratio);

private:
    static constexpr uint32_t kWindows = 32;

    static double Tap(double x);
    void          ForgetLastSample();

    double         base_      = 1.0;
    double         pos_       = -1.0;
    int16_t        hist_[3][kMaxChannels] = {};
    uint32_t       blocks_    = 0;
    bool           started_   = false;
    bool           estimated_ = false;
    double         win_frames_[kWindows]  = {};
    double         win_nominal_[kWindows] = {};
    uint32_t       win_head_  = 0;
    uint32_t       win_count_ = 0;
    DevicePosition prev_;
    bool           have_prev_ = false;
};
