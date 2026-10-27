#include "object_url.h"

QString ObjectUrl(const QString& base_url, const QString& name) {
    QString url = base_url;
    while (url.endsWith(QLatin1Char('/'))) url.chop(1);
    return url + QLatin1Char('/') + name;
}
