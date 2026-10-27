#pragma once

#include <QString>

bool    IsSafeBundleName(const QString& name);
QString SafeBundleNameFrom(const QString& text);
QString BundleNameRule();
