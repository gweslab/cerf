#pragma once

#include "../manager_windows.h"

#include <cerfcore/core/service.h>

#include <QVariantMap>

#include <optional>
#include <string>

class QtManagerWindowOpener : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OpenAbout(const std::string& device_line);
    void OpenSettings();
    void OpenTutorial();
    bool EditLiveCustomizations(bool force_reboot, std::optional<int> ce_major, cerffrontend::GuestReset& reset);

private:
    QVariantMap Placement() const;
};
