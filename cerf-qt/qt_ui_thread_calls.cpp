#include "qt_ui_thread_calls.h"

#include "qt_ui_thread.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QMetaObject>

#include <memory>
#include <thread>
#include <utility>

REGISTER_SERVICE(QtUiThreadCalls);

bool QtUiThreadCalls::Run(std::function<void()> job) {
    if (OnUiThread()) {
        job();
        return true;
    }
    const auto                   done   = std::make_shared<bool>(false);
    const std::thread::id        caller = std::this_thread::get_id();
    std::unique_lock<std::mutex> lock(mutex_);
    if (closed_) return false;
    QMetaObject::invokeMethod(
        &context_,
        [this, job = std::move(job), done, caller] {
            {
                std::lock_guard<std::mutex> guard(mutex_);
                if (closed_) return;
            }
            {
                const cerfcore::CerfEmulator::ResolverBorrow borrow(emu_, caller);
                job();
            }
            std::lock_guard<std::mutex> guard(mutex_);
            *done = true;
            finished_.notify_all();
        },
        Qt::QueuedConnection);
    finished_.wait(lock, [&] { return *done || closed_; });
    return *done;
}

void QtUiThreadCalls::Close() {
    std::lock_guard<std::mutex> lock(mutex_);
    closed_ = true;
    finished_.notify_all();
}
