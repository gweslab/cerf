#include "shutdown_teardown.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>
#include <cerfcore/execution/jit_runner.h>

namespace cerffrontend {

REGISTER_SERVICE(ShutdownTeardown);

bool ShutdownTeardown::Begin() {
    if (active_) return false;
    active_ = true;
    emu_.Get<cerfcore::JitRunner>().RequestStop();
    start_ = std::chrono::steady_clock::now();
    return true;
}

ShutdownTeardown::Step ShutdownTeardown::Poll() {
    if (emu_.Get<cerfcore::JitRunner>().Stopped()) return Step::kStopped;
    if (std::chrono::steady_clock::now() - start_ < std::chrono::milliseconds(kGraceMs))
        return Step::kWaiting;
    LOG(Caution, "ShutdownTeardown: JIT did not stop within %ums of close\n", kGraceMs);
    return Step::kWedged;
}

}
