#include "lcd_content_latch.h"

#include "../core/log.h"
#include "../cpu/emulated_memory.h"

namespace {

constexpr size_t kProbeStride = 251;

}

bool LcdContentLatch::ProbeAndLatch(EmulatedMemory& mem,
                                    uint32_t fb_pa,
                                    size_t   fb_bytes) {
    if (latched_.load(std::memory_order_acquire)) return true;
    if (fb_bytes == 0)                            return false;

    /* TryTranslate - fb_pa may not be inside a declared region yet
       in the early mode-program-before-fb-write window; Translate
       halts on unmapped, TryTranslate returns nullptr so the latch
       just stays false until CE publishes a real fb. */
    const uint8_t* fb = mem.TryTranslate(fb_pa);
    if (!fb) return false;
    return ProbeAndLatch(fb, fb_bytes);
}

bool LcdContentLatch::ProbeAndLatch(const uint8_t* fb, size_t fb_bytes) {
    if (latched_.load(std::memory_order_acquire)) return true;
    if (!fb || fb_bytes == 0)                     return false;

    /* One walk computes both signals: any nonzero sample, and an
       FNV-1a signature of the samples for the post-Rearm baseline
       comparison. */
    bool     nonzero = false;
    uint64_t sig     = 14695981039346656037ull;
    for (size_t i = 0; i < fb_bytes; i += kProbeStride) {
        const uint8_t b = fb[i];
        nonzero |= (b != 0);
        sig = (sig ^ b) * 1099511628211ull;
    }

    if (rearmed_.load(std::memory_order_acquire)) {
        if (!have_baseline_.load(std::memory_order_acquire)) {
            baseline_sig_.store(sig, std::memory_order_release);
            have_baseline_.store(true, std::memory_order_release);
            return false;
        }
        if (!nonzero) {
            /* Content vanished (e.g. hard-reset RAM wipe landed after the
               baseline was taken) - rebase so any future content latches. */
            baseline_sig_.store(sig, std::memory_order_release);
            return false;
        }
        if (sig == baseline_sig_.load(std::memory_order_acquire)) return false;
        rearmed_.store(false, std::memory_order_release);
        have_baseline_.store(false, std::memory_order_release);
    }

    if (!nonzero) return false;
    latched_.store(true, std::memory_order_release);
    LOG(Lcd, "content latch: fresh content latched (sig=0x%016llX)\n",
        (unsigned long long)sig);
    return true;
}

void LcdContentLatch::Rearm() {
    have_baseline_.store(false, std::memory_order_release);
    rearmed_.store(true, std::memory_order_release);
    latched_.store(false, std::memory_order_release);
    LOG(Lcd, "content latch: rearmed (guest reset)\n");
}
