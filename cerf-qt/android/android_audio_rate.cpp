#include "android_audio_rate.h"

namespace cerffrontend {

uint32_t AaudioRateMultiple(uint32_t rate_hz) {
    if (rate_hz == 0u || rate_hz >= kAaudioMinRateHz) return 1u;
    return (kAaudioMinRateHz + rate_hz - 1u) / rate_hz;
}

}
