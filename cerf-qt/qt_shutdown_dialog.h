#pragma once

#include "shutdown_prompt.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QPointer>
#include <QVariant>
#include <QVariantMap>

class QtEmulatorWindow;

class QtShutdownDialog : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override;
    void Show(cerffrontend::ShutdownTrigger trigger);

private:
    void                         StopCountdown();
    void                         FollowSleep();
    QVariantMap                  Texts(cerffrontend::ShutdownTrigger trigger);
    cerffrontend::ShutdownChoice Choice(const QVariant& result);
    void OfferAc(cerffrontend::ShutdownTrigger trigger, cerffrontend::ShutdownChoice choice);
    void Perform(cerffrontend::ShutdownTrigger trigger, cerffrontend::ShutdownChoice choice);
    void SaveAndExit();

    QtEmulatorWindow*             window_       = nullptr;
    QPointer<QObject>             dialog_;
    bool                          open_         = false;
    bool                          withdrawn_    = false;
    cerffrontend::ShutdownTrigger open_trigger_ = cerffrontend::ShutdownTrigger::WindowClose;
};
