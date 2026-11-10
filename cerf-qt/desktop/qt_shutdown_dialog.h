#pragma once

#include <cerfcore/core/service.h>
#include <cerfcore/state/shutdown_choice.h>

class QDialog;

class QtShutdownDialog : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    cerfcore::ShutdownChoice Show(cerfcore::ShutdownTrigger trigger);
    bool IsOpen() const { return open_ != nullptr; }
    void DismissPrompt();

private:
    void OfferAc(cerfcore::ShutdownTrigger trigger, cerfcore::ShutdownChoice choice);

    QDialog* open_      = nullptr;
    bool     dismissed_ = false;
};
