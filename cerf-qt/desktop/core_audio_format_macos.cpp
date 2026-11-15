#include "core_audio_format.h"

namespace cerffrontend {

AudioStreamBasicDescription LinearPcmDescription(const cerfcore::AudioFormat& format) {
    const uint32_t              frame = format.FrameBytes();
    AudioStreamBasicDescription fmt{};
    fmt.mSampleRate       = format.rate_hz;
    fmt.mFormatID         = kAudioFormatLinearPCM;
    fmt.mFormatFlags      = (format.bits == 16u ? kAudioFormatFlagIsSignedInteger : 0u) | kAudioFormatFlagIsPacked;
    fmt.mBytesPerPacket   = frame;
    fmt.mFramesPerPacket  = 1u;
    fmt.mBytesPerFrame    = frame;
    fmt.mChannelsPerFrame = format.channels;
    fmt.mBitsPerChannel   = format.bits;
    return fmt;
}

}
