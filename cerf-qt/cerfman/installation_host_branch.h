#pragma once

#include <QString>

#include <cstdint>
#include <vector>

QString              ReleaseMarker(const QString& host_branch);
std::vector<uint8_t> DefaultHostKeyVks(const QString& host_branch);
