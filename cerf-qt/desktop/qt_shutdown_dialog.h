#pragma once

#include <cerfcore/core/service.h>
#include <cerfcore/state/shutdown_choice.h>

class QDialog;

class QtShutdownDialog : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    cerfcore::ShutdownChoice Show(cerfcore::ShutdownTrigger trigger);
    void DismissAsCancel();

private:
    QDialog* open_ = nullptr;
};
