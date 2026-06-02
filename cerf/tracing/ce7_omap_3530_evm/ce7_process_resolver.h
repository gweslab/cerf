#pragma once

#include "../trace_manager.h"

#include <cstdint>
#include <string>

#if CERF_DEV_MODE

/* CE7 FCSE-aware process resolver. Builds name -> FCSE PID by hooking
   NKCreateProcess + CreateNewProcHelper. Predicates returned by
   PidPredicateForName admit a hook fire only when the current process's
   FCSE PID matches the named EXE's PID. */
namespace ce7_resolver {

uint8_t        CurrentFcsePid(const TraceContext& c);
TracePredicate PidPredicateForName(std::string image_name);

}  /* namespace ce7_resolver */

#endif  /* CERF_DEV_MODE */
