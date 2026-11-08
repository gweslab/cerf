#pragma once

#include <cerfcore/host/external_display.h>

#include <QPointer>
#include <QString>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>

namespace cerfcore {
class CerfEmulator;
class FrameSource;
}

class QtExternalWindow;

class QtExternalDisplay : public cerfcore::ExternalDisplay {
public:
    QtExternalDisplay(cerfcore::CerfEmulator& emu, cerfcore::FrameSource& source, QString title,
                      std::function<void()> on_eject);
    ~QtExternalDisplay() override;

    void Open(uint32_t surf_w, uint32_t surf_h) override;
    void Close() override;
    void SetSurfaceSize(uint32_t w, uint32_t h) override;

private:
    void RunOnUi(std::function<void()> job);

    cerfcore::CerfEmulator&                     emu_;
    cerfcore::FrameSource&                      source_;
    QString                                     title_;
    std::function<void()>                       on_eject_;
    int                                         source_id_ = 0;
    std::shared_ptr<QPointer<QtExternalWindow>> window_ = std::make_shared<QPointer<QtExternalWindow>>();
    std::atomic<bool>                           open_{false};
};
