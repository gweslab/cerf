#include "frontend_dialogs.h"

#include "../cerfman/file_access.h"
#include "../qt_emulator_window.h"
#include "../qt_file_filters.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QStringList>
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>

namespace {

class QtFrontendDialogs : public cerffrontend::FrontendDialogs {
public:
    using cerffrontend::FrontendDialogs::FrontendDialogs;

    std::string ChooseStateFile(bool save, const std::string& default_path) override {
        const QVariant result = emu_.Get<QtEmulatorWindow>().RunDialog(
            QStringLiteral("EmulatorFileDialog"),
            QVariantMap{{QStringLiteral("nameFilters"),
                         QStringList{QStringLiteral("State image (*.img)"), AllFilesNameFilter()}},
                        {QStringLiteral("save"), save},
                        {QStringLiteral("defaultSuffix"), QStringLiteral("img")},
                        {QStringLiteral("selectedFile"), QUrl::fromLocalFile(QString::fromStdString(default_path))}});
        const QVariantList chosen = result.toList();
        if (chosen.isEmpty()) return {};
        return emu_.Get<FileAccess>().LocalPath(QUrl(chosen.front().toString())).toStdString();
    }
};

}

REGISTER_SERVICE_AS(QtFrontendDialogs, cerffrontend::FrontendDialogs);
