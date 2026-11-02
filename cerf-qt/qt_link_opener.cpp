#include "link_opener.h"
#include "link_target.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>

#include <QDesktopServices>
#include <QUrl>

namespace {

class QtLinkOpener : public cerffrontend::LinkOpener {
public:
    using cerffrontend::LinkOpener::LinkOpener;

    void Open(const std::string& url) override {
        const QString target = LinkTarget(QString::fromStdString(url));
        if (target.isEmpty()) {
            LOG(Caution, "QtLinkOpener: %s has no target in this copy\n", url.c_str());
            return;
        }
        if (!QDesktopServices::openUrl(QUrl(target)))
            LOG(Caution, "QtLinkOpener: no handler opened %s\n", target.toUtf8().constData());
    }
};

}

REGISTER_SERVICE_AS(QtLinkOpener, cerffrontend::LinkOpener);
