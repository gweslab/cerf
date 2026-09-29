#pragma once

#include <cstdint>

namespace cerf_vr41xx_piu_detail {

uint16_t StateAfterCntWrite(uint16_t state, uint16_t old_cfg, uint16_t new_cfg, uint16_t ascn);

}
