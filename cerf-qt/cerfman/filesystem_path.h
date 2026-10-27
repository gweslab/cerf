#pragma once

#include <QString>

#include <filesystem>
#include <system_error>

std::filesystem::path PathOf(const QString& text);
QString               PathText(const std::filesystem::path& path);
QString               ErrorCodeText(const std::error_code& ec);
bool                  RemoveEntry(const std::filesystem::path& path, QString& error);
bool                  EntryExists(const std::filesystem::path& path);
QString               PathDisplayName(const QString& path);
QString               LocationName(const QString& path);
bool                  MakeDirectory(const QString& path, QString& error);
bool                  CopyFileTo(const std::filesystem::path& from, const std::filesystem::path& to, QString& error);
