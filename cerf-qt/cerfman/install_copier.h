#pragma once

#include "install_retry_gate.h"
#include "json_file.h"

#include "../executable_names_text.h"

#include <QString>

#include <filesystem>
#include <vector>

#define CERF_RETIRED_FRONTEND     "cerf-qt"
#define CERF_RETIRED_LAUNCHER_APP "CE Runtime Foundation Launcher.app"

inline constexpr const char* kRetiredEntries[] = {CERF_LAUNCHER_NAME, CERF_LAUNCHER_NAME ".sh", CERF_RETIRED_FRONTEND,
                                                  CERF_RETIRED_LAUNCHER_APP};
inline constexpr const char* kRetiredExecutables[] = {
    CERF_LAUNCHER_NAME "/" CERF_LAUNCHER_NAME ".exe", CERF_LAUNCHER_NAME "/" CERF_LAUNCHER_NAME, CERF_RETIRED_FRONTEND,
    CERF_RETIRED_LAUNCHER_APP "/Contents/MacOS/" CERF_LAUNCHER_NAME};

class InstallCopier {
public:
    explicit InstallCopier(const InstallRetryGate& gate) : gate_(gate) {}

    bool Prepare(const QString& upgrade_dir, const QString& install_dir, QString& error);
    bool Apply(QString& error);

private:
    using CopyAction = bool (*)(const std::filesystem::path& source, const std::filesystem::path& destination,
                                QString& error);

    bool Step(const QString& title, const QString& what, const InstallRetryGate::Action& action,
              QString& error) const;
    bool ListBundles(QString& error);
    bool ListPayload(QString& error);
    void ListRetiredEntries();
    bool CopyAll(const std::vector<std::filesystem::path>& relatives, CopyAction copy, QString& error);
    bool RemoveRetiredEntries(QString& error);

    const InstallRetryGate&            gate_;
    std::filesystem::path              from_;
    std::filesystem::path              to_;
    Json                               staged_config_;
    std::vector<std::filesystem::path> bundles_;
    std::vector<std::filesystem::path> payload_;
    std::vector<const char*>           retired_;
};
