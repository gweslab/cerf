#include <cerfcore/host/file_chooser.h>

#include "../qt_file_filters.h"
#include "qt_main_window.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QFileDialog>
#include <QStringList>

namespace {

QString FilterString(const std::vector<cerfcore::FileChooserFilter>& filters) {
    return FileChooserNameFilters(filters).join(QStringLiteral(";;"));
}

class QtFileChooser : public cerfcore::FileChooser {
public:
    using cerfcore::FileChooser::FileChooser;

    std::string ChooseFile(const std::string& title,
                           const std::vector<cerfcore::FileChooserFilter>& filters) override {
        const QString path = QFileDialog::getOpenFileName(emu_.Get<QtMainWindow>().Window(),
                                                          QString::fromStdString(title), QString(),
                                                          FilterString(filters));
        return path.toStdString();
    }

    std::vector<std::string> ChooseFiles(
        const std::string& title, const std::vector<cerfcore::FileChooserFilter>& filters) override {
        std::vector<std::string> out;
        const QStringList paths = QFileDialog::getOpenFileNames(
            emu_.Get<QtMainWindow>().Window(), QString::fromStdString(title), QString(),
            FilterString(filters));
        for (const QString& p : paths) out.push_back(p.toStdString());
        return out;
    }
};

}

REGISTER_SERVICE_AS(QtFileChooser, cerfcore::FileChooser);
