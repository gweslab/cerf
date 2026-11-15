#pragma once

#include <AudioToolbox/AudioToolbox.h>

#include <cerfcore/host/audio_format.h>

namespace cerffrontend {

AudioStreamBasicDescription LinearPcmDescription(const cerfcore::AudioFormat& format);

}
