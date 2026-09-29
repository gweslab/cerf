#include "vr41xx_cmu.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"

void Vr41xxCmu::RequireTclock(uint16_t mask_bit, const char* operation) const {
    const uint16_t mask = ClockMask();
    if ((mask & mask_bit) == 0u) {
        emu_.Get<Fatal>().Die("Vr41xxCmu: %s with CMUCLKMSK 0x%04X masking its TClock; the unit "
                              "without TClock is not modeled", operation, mask);
    }
}

void Vr41xxCmu::RegisterClockUser(uint16_t mask_bit, const char* unit,
                                  std::function<bool()> scanning) {
    clock_users_.push_back(ClockUser{mask_bit, unit, std::move(scanning)});
}

void Vr41xxCmu::ClockMaskWriting(uint16_t next) const {
    const uint16_t mask = ClockMask();
    for (const ClockUser& user : clock_users_) {
        if ((mask & user.mask_bit) != 0u && (next & user.mask_bit) == 0u && user.scanning()) {
            emu_.Get<Fatal>().Die("Vr41xxCmu: CMUCLKMSK 0x%04X -> 0x%04X masks the %s TClock "
                                  "during a scan; the unit without TClock is not modeled", mask,
                                  next, user.unit);
        }
    }
}
