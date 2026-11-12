#include <cerfcore/host/file_chooser.h>

#include "cerfman/file_access.h"
#include "qt_file_filters.h"
#include "qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QUrl>
#include <QVariantList>
#include <QVariantMap>

namespace {

class QtFileChooser : public cerfcore::FileChooser {
public:
    using cerfcore::FileChooser::FileChooser;

    std::string ChooseFile(const std::string& title,
                           const std::vector<cerfcore::FileChooserFilter>& filters) override {
        const std::vector<std::string> picked = Pick(title, filters, false);
        return picked.empty() ? std::string() : picked.front();
    }

    std::vector<std::string> ChooseFiles(const std::string&                             title,
                                         const std::vector<cerfcore::FileChooserFilter>& filters) override {
        return Pick(title, filters, true);
    }

private:
    std::vector<std::string> Pick(const std::string& title, const std::vector<cerfcore::FileChooserFilter>& filters,
                                  bool multiple) {
        const QVariant result = emu_.Get<QtEmulatorWindow>().RunDialog(
            QStringLiteral("EmulatorFileDialog"),
            QVariantMap{{QStringLiteral("title"), QString::fromStdString(title)},
                        {QStringLiteral("nameFilters"), FileChooserNameFilters(filters)},
                        {QStringLiteral("multiple"), multiple}});
        std::vector<std::string> out;
        const FileAccess&        files = emu_.Get<FileAccess>();
        for (const QVariant& url : result.toList()) {
            const QString path = files.LocalPath(QUrl(url.toString()));
            if (!path.isEmpty()) out.push_back(path.toStdString());
        }
        return out;
    }
};

}

REGISTER_SERVICE_AS(QtFileChooser, cerfcore::FileChooser);
