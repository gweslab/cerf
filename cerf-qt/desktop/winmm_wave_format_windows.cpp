#define NOMINMAX
#include "winmm_wave_format.h"

namespace cerffrontend {

WAVEFORMATEX PcmWaveFormat(const cerfcore::AudioFormat& format) {
    WAVEFORMATEX fmt{};
    fmt.wFormatTag      = WAVE_FORMAT_PCM;
    fmt.nChannels       = format.channels;
    fmt.nSamplesPerSec  = format.rate_hz;
    fmt.wBitsPerSample  = format.bits;
    fmt.nBlockAlign     = static_cast<WORD>(format.FrameBytes());
    fmt.nAvgBytesPerSec = format.rate_hz * fmt.nBlockAlign;
    fmt.cbSize          = 0;
    return fmt;
}

}
