#pragma once

#include <cstdint>

/* Intel 81341/81342 Developer's Manual Table 442 (printed p. 726): PFR XSI bus
   frequency status [20:19] = 00 runs the internal bus at the core frequency
   divided by 2. */
inline constexpr uint64_t kIop13xxCoreCyclesPerBusClock = 2u;
