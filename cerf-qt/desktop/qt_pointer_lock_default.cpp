#include "qt_pointer_lock.h"

namespace {

class NoPointerLock final : public QtPointerLock {
public:
    bool Lock(QWidget&) override { return false; }
    void Unlock() override {}
    bool CanWarp() override { return true; }
};

}

std::unique_ptr<QtPointerLock> MakeQtPointerLock(QtRelativeMotionSink&) { return std::make_unique<NoPointerLock>(); }
