#include "link_target.h"

#include "play_store_copy.h"
#include "product_links.h"

#include <QStringList>
#include <QUrl>

namespace {

QString BareHost(const QUrl& url) {
    QString host = url.host().toLower();
    if (host.startsWith(QLatin1String("www."))) host.remove(0, 4);
    return host;
}

QString TrimmedPath(QString path) {
    while (path.endsWith(QLatin1Char('/'))) path.chop(1);
    return path;
}

QStringList Words(const char* text) { return QString::fromUtf8(text).split(QLatin1Char(' '), Qt::SkipEmptyParts); }

bool UnderPrefix(const QUrl& link, const QUrl& prefix) {
    if (BareHost(link) != BareHost(prefix)) return false;
    const QString base = TrimmedPath(prefix.path());
    return base.isEmpty() || link.path() == base || link.path().startsWith(base + QLatin1Char('/'));
}

bool RemovedUrl(const QUrl& link) {
    for (const QString& prefix : Words(CERF_PLAY_STORE_REMOVED_URLS))
        if (UnderPrefix(link, QUrl(prefix))) return true;
    return false;
}

bool OnWebsite(const QUrl& link) {
    return BareHost(link) == BareHost(QUrl(QString::fromUtf8(cerffrontend::kWebsiteUrl)));
}

}

QString LinkTarget(const QString& url) {
    if (!PlayStoreCopy()) return url;
    QUrl link(url);
    if (link.scheme() != QLatin1String("http") && link.scheme() != QLatin1String("https")) return url;
    if (RemovedUrl(link)) return QString();
    if (!OnWebsite(link)) return url;
    if (Words(CERF_PLAY_STORE_REMOVED_PATHS).contains(TrimmedPath(link.path()))) return QString();
    link.setHost(QUrl(QString::fromUtf8(cerffrontend::kStoreWebsiteUrl)).host());
    return link.toString();
}
