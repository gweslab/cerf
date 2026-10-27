#include "guest_reset_text.h"

namespace cerffrontend {

GuestReset GuestResetFromValue(std::string_view value) {
    if (value == kSoftResetValue) return GuestReset::kSoft;
    if (value == kHardResetValue) return GuestReset::kHard;
    return GuestReset::kNone;
}

}
