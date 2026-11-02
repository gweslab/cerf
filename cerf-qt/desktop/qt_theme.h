#pragma once

#include <cerfcore/core/instance_gate.h>
#include <cerfcore/core/service.h>

#include <QObject>

class QtTheme : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void ApplyStyle();
    bool IsDark() const { return dark_; }

private:
    void ApplyPalette();

    const cerfcore::InstanceGate gate_{emu_};
    QObject                      scheme_receiver_;
    bool                         dark_ = false;
};
