#pragma once

#include <cstdint>

struct Sa11xxAudioConfig {
    uint32_t    ddar_mask;
    uint32_t    ddar_value;
    uint16_t    channels;
    uint16_t    bits_per_sample;
    uint32_t    max_page_bytes;
    bool        allow_resampler;
    const char* log_tag;
};
