#include "pcm_format.h"

namespace cerffrontend {

bool PcmFormatSupported(const cerfcore::AudioFormat& format) {
    return (format.bits == 8u || format.bits == 16u) && format.channels != 0u && format.rate_hz != 0u;
}

}
