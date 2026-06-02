#pragma once

#include "../trace_manager.h"

#include <cstdint>
#include <string>

#if CERF_DEV_MODE

/* Zune/Keel (CE5) process resolver, mirrors ce7_process_resolver:
   PidPredicateForName admits a fire only when current TTBR0 == the named
   EXE's (resolved by hooking CreateProcess + primary-thread bootstrap). */
namespace zune_resolver {

TracePredicate PidPredicateForName(std::string image_name);

}  /* namespace zune_resolver */

#endif  /* CERF_DEV_MODE */
