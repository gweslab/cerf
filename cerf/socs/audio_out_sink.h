#pragma once

#include <cstdint>
#include <functional>

/* PCM-out target for a Pxa255Dma audio channel: BeginAudioOut registers on_block_done,
   which the sink fires when a queued block finishes playing; the DMA delivers the next
   descriptor on that callback, so the ring is paced by block-completion. Non-Service so
   a Peripheral can implement it without a Service diamond. */
class AudioOutSink {
public:
    virtual ~AudioOutSink() = default;

    virtual void BeginAudioOut(std::function<void()> on_block_done) = 0;
    virtual void QueueOutput(const void* host_bytes, uint32_t length) = 0;
    virtual void StopAudioOut() = 0;
};
