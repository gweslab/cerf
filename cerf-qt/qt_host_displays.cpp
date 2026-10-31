#include <cerfcore/host/host_displays.h>

#include "qt_ui_thread_calls.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/instance_gate.h>
#include <cerfcore/core/log.h>

#include <QGuiApplication>
#include <QObject>
#include <QScreen>

#include <atomic>
#include <cmath>

namespace {

class QtHostDisplays : public cerfcore::HostDisplays {
public:
    using cerfcore::HostDisplays::HostDisplays;

    void OnReady() override {
        emu_.Get<QtUiThreadCalls>().Run([this] {
            for (QScreen* screen : QGuiApplication::screens()) Watch(screen);
            QObject::connect(qGuiApp, &QGuiApplication::screenAdded, &context_, gate_.Bind([this](QScreen* screen) {
                                 Watch(screen);
                                 RequestRecompute();
                             }));
            QObject::connect(qGuiApp, &QGuiApplication::screenRemoved, &context_,
                             gate_.Bind([this] { RequestRecompute(); }));
            Recompute();
        });
    }

    int HighestRefreshRate() override { return refresh_.load(std::memory_order_acquire); }

private:
    void Watch(QScreen* screen) {
        QObject::connect(screen, &QScreen::refreshRateChanged, &context_, gate_.Bind([this] { RequestRecompute(); }));
    }

    void RequestRecompute() {
        if (recompute_pending_) return;
        recompute_pending_ = true;
        QMetaObject::invokeMethod(&context_, gate_.Bind([this] {
                                      recompute_pending_ = false;
                                      Recompute();
                                  }),
                                  Qt::QueuedConnection);
    }

    void Recompute() {
        int refresh = 0;
        for (const QScreen* screen : QGuiApplication::screens()) {
            const int hz = static_cast<int>(std::lround(screen->refreshRate()));
            if (hz > refresh) refresh = hz;
        }
        refresh_.store(refresh, std::memory_order_release);
        LOG(Lcd, "QtHostDisplays: highest %d Hz\n", refresh);
    }

    const cerfcore::InstanceGate gate_{emu_};
    QObject                      context_;
    bool                         recompute_pending_ = false;
    std::atomic<int>             refresh_{0};
};

}

REGISTER_SERVICE_AS(QtHostDisplays, cerfcore::HostDisplays);
