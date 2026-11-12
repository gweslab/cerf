#include "qt_pointer_lock.h"

namespace {

class NoPointerControl final : public QtPointerLock {
public:
    bool Lock(QWindow&) override { return false; }
    void Unlock() override {}
    bool CanWarp() override { return false; }
};

}

std::unique_ptr<QtPointerLock> MakeQtPointerLock(QtRelativeMotionSink&) { return std::make_unique<NoPointerControl>(); }
