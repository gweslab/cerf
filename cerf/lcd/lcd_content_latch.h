#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>

class EmulatedMemory;

/* Re-probing every frame would un-latch when CE clears the fb to
   black, blinking the host window between fb and UART screen.
   One-way latch is intentional; Rearm is the single sanctioned
   un-latch, for guest reset. */
class LcdContentLatch {
public:
    bool ProbeAndLatch(EmulatedMemory& mem, uint32_t fb_pa, size_t fb_bytes);

    /* Same probe over an fb that already lives in host memory (e.g. a
       display controller's internal VRAM). */
    bool ProbeAndLatch(const uint8_t* fb, size_t fb_bytes);

    bool Latched() const {
        return latched_.load(std::memory_order_acquire);
    }

    /* Guest reset: un-latch; re-latch only on nonzero content DIFFERENT
       from the next probe's baseline. A plain un-latch re-fires on the
       very next probe after a soft reset (old fb bytes stay in RAM) and
       the UART screen is never seen. */
    void Rearm();

private:
    std::atomic<bool>     latched_{false};
    std::atomic<bool>     rearmed_{false};
    std::atomic<bool>     have_baseline_{false};
    std::atomic<uint64_t> baseline_sig_{0};
};
