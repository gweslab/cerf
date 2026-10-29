#include "qt_ui_thread_calls.h"

#include "qt_ui_thread.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/fatal.h>

#include <QMetaObject>

#include <exception>
#include <memory>
#include <utility>

REGISTER_SERVICE(QtUiThreadCalls);

bool QtUiThreadCalls::Run(std::function<void()> job) {
    cerfcore::Fatal& fatal = emu_.Get<cerfcore::Fatal>();
    if (OnUiThread()) {
        if (const std::exception_ptr failure = fatal.RunForWaiter(job)) cerfcore::Fatal::Raise(failure);
        return true;
    }
    const auto                   done    = std::make_shared<bool>(false);
    const auto                   failure = std::make_shared<std::exception_ptr>();
    std::unique_lock<std::mutex> lock(mutex_);
    if (closed_) return false;
    QMetaObject::invokeMethod(
        &context_,
        [this, &fatal, job = std::move(job), done, failure] {
            {
                std::lock_guard<std::mutex> guard(mutex_);
                if (closed_) return;
            }
            const std::exception_ptr halt = fatal.RunForWaiter(job);
            {
                std::lock_guard<std::mutex> guard(mutex_);
                if (!closed_) {
                    *failure = halt;
                    *done    = true;
                    finished_.notify_all();
                    return;
                }
            }
            if (halt) fatal.GuardTeardown([&halt] { cerfcore::Fatal::Raise(halt); });
        },
        Qt::QueuedConnection);
    finished_.wait(lock, [&] { return *done || closed_; });
    if (*failure) cerfcore::Fatal::Raise(*failure);
    return *done;
}

void QtUiThreadCalls::Close() {
    std::lock_guard<std::mutex> lock(mutex_);
    closed_ = true;
    finished_.notify_all();
}
