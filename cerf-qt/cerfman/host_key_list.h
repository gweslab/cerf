#pragma once

#include <QVariantList>

#include <cstdint>
#include <vector>

QVariantList         HostKeyVariantList(const std::vector<uint8_t>& vks);
std::vector<uint8_t> HostKeyVks(const QVariantList& vks);
