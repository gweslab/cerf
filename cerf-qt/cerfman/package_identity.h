#pragma once

#include <QString>

template <class Package>
bool IsPackage(const Package& package, const QString& category, const QString& key) {
    return package.category == category && package.key == key;
}
