#include "frontend_dialogs.h"

#include "qt_main_window.h"
#include "../qt_file_filters.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QFileDialog>
#include <QMessageBox>
#include <QStringList>

namespace {

class QtFrontendDialogs : public cerffrontend::FrontendDialogs {
public:
    using cerffrontend::FrontendDialogs::FrontendDialogs;

    std::string ChooseStateFile(bool save, const std::string& default_path) override {
        QFileDialog dialog(emu_.Get<QtMainWindow>().Window());
        dialog.setNameFilters(
            QStringList{QStringLiteral("State image (*.img)"), AllFilesNameFilter()});
        dialog.setDefaultSuffix(QStringLiteral("img"));
        dialog.selectFile(QString::fromStdString(default_path));
        dialog.setAcceptMode(save ? QFileDialog::AcceptSave : QFileDialog::AcceptOpen);
        dialog.setFileMode(save ? QFileDialog::AnyFile : QFileDialog::ExistingFile);
        if (dialog.exec() != QDialog::Accepted || dialog.selectedFiles().isEmpty()) return {};
        return dialog.selectedFiles().front().toStdString();
    }

    bool ConfirmWarning(const std::string& title, const std::string& text) override {
        return QMessageBox::warning(emu_.Get<QtMainWindow>().Window(), QString::fromStdString(title),
                                    QString::fromStdString(text),
                                    QMessageBox::Yes | QMessageBox::No,
                                    QMessageBox::No) == QMessageBox::Yes;
    }
};

}

REGISTER_SERVICE_AS(QtFrontendDialogs, cerffrontend::FrontendDialogs);
