#include "link_opener.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>

#include <QDesktopServices>
#include <QUrl>

namespace {

class QtLinkOpener : public cerffrontend::LinkOpener {
public:
    using cerffrontend::LinkOpener::LinkOpener;

    void Open(const std::string& url) override {
        if (!QDesktopServices::openUrl(QUrl(QString::fromStdString(url))))
            LOG(Caution, "QtLinkOpener: no handler opened %s\n", url.c_str());
    }
};

}

REGISTER_SERVICE_AS(QtLinkOpener, cerffrontend::LinkOpener);
