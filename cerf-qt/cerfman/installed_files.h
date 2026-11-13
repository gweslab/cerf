#pragma once

#include "json_file.h"

#include <QString>
#include <QStringList>

#include <filesystem>
#include <optional>

enum class InstalledFileRemoval { kRemoved, kSkipped, kFailed };

std::optional<QStringList>           InstalledFileList(const Json& record);
Json                                 InstalledFileRecord(const QStringList& files);
QStringList                          DroppedFiles(const QStringList& before, const QStringList& now);
std::optional<std::filesystem::path> InstalledFileEntry(const QString& relative);
bool AdoptInstalledName(const std::filesystem::path& root, const std::filesystem::path& entry, QString& error);
InstalledFileRemoval                 RemoveInstalledFile(const std::filesystem::path& root,
                                                         const std::filesystem::path& entry, QString& error);
