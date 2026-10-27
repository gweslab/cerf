#pragma once

#include <QElapsedTimer>
#include <QTimer>

#include <deque>
#include <functional>

class StripPressDelay {
public:
    enum class Step { kPress, kRelease, kCancel };
    using Sink = std::function<void(Step step, int index)>;

    explicit StripPressDelay(Sink sink);

    void Begin(int index);
    void End(int index);
    void Cancel(int index);
    void HandOver(int index);
    void Drop();

private:
    struct Queued {
        Step   step;
        int    index;
        qint64 due_ms;
    };

    void Decide();
    void Enqueue(Step step, int index, qint64 due_ms);
    void DeliverDue();
    void DeliverAll();
    void Arm();

    Sink               sink_;
    QElapsedTimer      clock_;
    QTimer             tap_timer_;
    QTimer             due_timer_;
    std::deque<Queued> queue_;
    qint64             free_at_ms_   = 0;
    qint64             down_ms_      = 0;
    qint64             press_due_ms_ = 0;
    int                current_      = -1;
    bool               decided_      = false;
};
