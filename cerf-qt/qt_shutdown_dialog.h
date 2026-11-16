#pragma once

#include "shutdown_prompt.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QPointer>
#include <QVariant>
#include <QVariantMap>

#include <cstdint>
#include <vector>

class QtEmulatorWindow;

class QtShutdownDialog : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override;
    void Show(cerffrontend::ShutdownTrigger trigger);

private:
    void                         StopCountdown();
    void                         FollowSleep();
    uint32_t                     SleepSettleMs();
    void                         ShowDialog(cerffrontend::ShutdownTrigger trigger);
    QVariantMap                  Texts(cerffrontend::ShutdownTrigger trigger);
    cerffrontend::ShutdownChoice Choice(const QVariant& result);
    void OfferAc(cerffrontend::ShutdownTrigger trigger, cerffrontend::ShutdownChoice choice);
    void Perform(cerffrontend::ShutdownTrigger trigger, cerffrontend::ShutdownChoice choice);
    void SaveAndExit(bool suspend_host);

    QtEmulatorWindow*                         window_       = nullptr;
    QPointer<QObject>                         dialog_;
    std::vector<cerffrontend::ShutdownAction> shown_actions_;
    bool                                      open_         = false;
    bool                                      withdrawn_    = false;
    bool                                      saving_       = false;
    uint32_t                                  sleep_changes_ = 0;
    cerffrontend::ShutdownTrigger             open_trigger_ = cerffrontend::ShutdownTrigger::WindowClose;
};
