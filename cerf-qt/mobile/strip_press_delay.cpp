#include "strip_press_delay.h"

#include "android_view_configuration.h"

#include <algorithm>
#include <utility>

StripPressDelay::StripPressDelay(Sink sink) : sink_(std::move(sink)) {
    clock_.start();
    tap_timer_.setSingleShot(true);
    tap_timer_.setInterval(AndroidTapTimeoutMs());
    due_timer_.setSingleShot(true);
    due_timer_.setTimerType(Qt::PreciseTimer);
    QObject::connect(&tap_timer_, &QTimer::timeout, [this] { Decide(); });
    QObject::connect(&due_timer_, &QTimer::timeout, [this] { DeliverDue(); });
}

void StripPressDelay::Begin(int index) {
    if (current_ != -1) Cancel(current_);
    current_ = index;
    decided_ = false;
    down_ms_ = clock_.elapsed();
    tap_timer_.start();
}

void StripPressDelay::End(int index) {
    if (index != current_) return;
    const qint64 hold = clock_.elapsed() - down_ms_;
    if (!decided_) Decide();
    free_at_ms_ = press_due_ms_ + hold;
    Enqueue(Step::kRelease, current_, free_at_ms_);
    current_ = -1;
}

void StripPressDelay::Cancel(int index) {
    if (index != current_) return;
    current_ = -1;
    tap_timer_.stop();
    if (!decided_) return;
    if (!queue_.empty() && queue_.back().step == Step::kPress) {
        queue_.pop_back();
        Arm();
        return;
    }
    free_at_ms_ = clock_.elapsed();
    Enqueue(Step::kCancel, index, free_at_ms_);
}

void StripPressDelay::HandOver(int index) {
    if (index != current_) return;
    if (!decided_) Decide();
    current_ = -1;
    DeliverAll();
    free_at_ms_ = clock_.elapsed();
}

void StripPressDelay::Drop() {
    tap_timer_.stop();
    due_timer_.stop();
    queue_.clear();
    current_ = -1;
}

void StripPressDelay::Decide() {
    tap_timer_.stop();
    decided_      = true;
    press_due_ms_ = std::max(clock_.elapsed(), free_at_ms_);
    Enqueue(Step::kPress, current_, press_due_ms_);
}

void StripPressDelay::Enqueue(Step step, int index, qint64 due_ms) {
    queue_.push_back(Queued{step, index, due_ms});
    DeliverDue();
}

void StripPressDelay::DeliverDue() {
    while (!queue_.empty() && queue_.front().due_ms <= clock_.elapsed()) {
        const Queued q = queue_.front();
        queue_.pop_front();
        sink_(q.step, q.index);
    }
    Arm();
}

void StripPressDelay::DeliverAll() {
    due_timer_.stop();
    while (!queue_.empty()) {
        const Queued q = queue_.front();
        queue_.pop_front();
        sink_(q.step, q.index);
    }
}

void StripPressDelay::Arm() {
    if (queue_.empty()) {
        due_timer_.stop();
        return;
    }
    due_timer_.start(static_cast<int>(std::max<qint64>(0, queue_.front().due_ms - clock_.elapsed())));
}
