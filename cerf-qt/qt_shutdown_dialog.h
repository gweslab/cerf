#pragma once

#include "shutdown_prompt.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QPointer>
#include <QVariant>
#include <QVariantMap>

#include <optional>
#include <vector>

class QtEmulatorWindow;

class QtShutdownDialog : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override;
    void Show(cerffrontend::ShutdownTrigger trigger);

private:
    using OptionalAction = std::optional<cerffrontend::ShutdownAction>;

    void           StopCountdown();
    void           FollowSleep();
    void           ShowDialog(cerffrontend::ShutdownTrigger trigger);
    QVariantMap    Texts(cerffrontend::ShutdownTrigger trigger);
    OptionalAction Choice(const QVariant& result);
    void           OfferAc(cerffrontend::ShutdownTrigger trigger, OptionalAction action);
    void           Perform(cerffrontend::ShutdownTrigger trigger, OptionalAction action);

    QtEmulatorWindow*                         window_       = nullptr;
    QPointer<QObject>                         dialog_;
    std::vector<cerffrontend::ShutdownAction> shown_actions_;
    bool                                      open_         = false;
    bool                                      withdrawn_    = false;
    cerffrontend::ShutdownTrigger             open_trigger_ = cerffrontend::ShutdownTrigger::WindowClose;
};
