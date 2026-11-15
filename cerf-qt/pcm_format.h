#pragma once

#include <cerfcore/host/audio_format.h>

namespace cerffrontend {

bool PcmFormatSupported(const cerfcore::AudioFormat& format);

}
