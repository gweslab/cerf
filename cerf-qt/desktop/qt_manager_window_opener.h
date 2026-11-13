#pragma once

#include "../manager_windows.h"

#include <cerfcore/core/service.h>

#include <QVariantMap>

#include <optional>
#include <string>

class QtManagerWindowOpener : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OpenSettings(const char* page, const std::string& device_line);
    void OpenTutorial();
    void EditLiveProperties(const char* page, bool force_reboot, std::optional<int> ce_major,
                            cerffrontend::LiveSheetFinished finished);

private:
    QVariantMap Placement() const;
};
