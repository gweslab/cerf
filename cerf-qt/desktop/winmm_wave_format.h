#pragma once

#include <windows.h>
#include <mmsystem.h>

#include <cerfcore/host/audio_format.h>

namespace cerffrontend {

WAVEFORMATEX PcmWaveFormat(const cerfcore::AudioFormat& format);

}
