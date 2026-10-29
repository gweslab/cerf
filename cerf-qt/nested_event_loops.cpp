#include "nested_event_loops.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>

#include <QEventLoop>

#include <utility>

REGISTER_SERVICE(NestedEventLoops);

void NestedEventLoops::Run(QEventLoop& loop) {
    if (quitting_) return;
    loops_.push_back(&loop);
    loop.exec();
    loops_.pop_back();
    if (loops_.empty() && after_) std::exchange(after_, {})();
}

void NestedEventLoops::QuitAll(std::function<void()> after) {
    LOG(Cerf, "NestedEventLoops: quitting %zu nested event loops before the instance exits\n", loops_.size());
    quitting_ = true;
    after_    = std::move(after);
    for (QEventLoop* loop : loops_) loop->quit();
}
