#pragma once

#include <cerfcore/core/service.h>

#include <QPointF>
#include <QRectF>
#include <QString>

#include <atomic>
#include <cstdint>
#include <string>

namespace cerffrontend {

class BootScreen : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override;

    std::string Label() const;
    uint64_t    RestartSerial() const { return restart_serial_.load(std::memory_order_acquire); }
    bool        Latched() const { return latched_.load(std::memory_order_acquire); }

    void Restart();
    void SetRestartLabel(const char* static_text);
    void OnFramebufferLatched();

    void SetHwLineHit(QRectF hit, QPointF scale);
    bool HitTestHwLine(int x, int y) const;

    const QString& SplashLogo() const { return splash_logo_; }
    const QString& SplashBadge() const { return splash_badge_; }

private:
    std::string              short_name_;
    QString                  splash_logo_;
    QString                  splash_badge_;
    QRectF                   hit_;
    QPointF                  scale_{1.0, 1.0};
    std::atomic<uint64_t>    restart_serial_{0};
    std::atomic<bool>        latched_{false};
    std::atomic<const char*> restart_label_{nullptr};
};

}
