#pragma once

#include "../manager_windows.h"

#include <QVariantMap>

#include <optional>
#include <string>

class QtManagerWindowOpener : public cerffrontend::ManagerWindows {
public:
    using cerffrontend::ManagerWindows::ManagerWindows;

    void OpenAbout(const std::string& device_line);
    void OpenSettings();
    void OpenTutorial();
    bool EditLiveCustomizations(bool force_reboot, std::optional<int> ce_major,
                                cerffrontend::GuestReset& reset) override;

private:
    QVariantMap Placement() const;
};
