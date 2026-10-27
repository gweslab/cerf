#include <cerfcore/host/number_prompt.h>

#include "qt_dialog_units.h"
#include "qt_main_window.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QDialog>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QRegularExpressionValidator>

namespace {

class QtNumberPrompt : public cerfcore::NumberPrompt {
public:
    using cerfcore::NumberPrompt::NumberPrompt;

    uint32_t AskAtLeast(const std::string& title, const std::string& caption,
                        uint32_t minimum) override {
        QDialog dialog(emu_.Get<QtMainWindow>().Window());
        dialog.setWindowTitle(QString::fromStdString(title));
        const QtDialogUnits du(dialog.fontMetrics());
        dialog.setFixedSize(du.X(210), du.Y(72));

        auto* label = new QLabel(QString::fromStdString(caption), &dialog);
        label->setGeometry(du.Rect(7, 7, 196, 12));
        auto* edit = new QLineEdit(QString::number(minimum), &dialog);
        edit->setGeometry(du.Rect(7, 24, 90, 12));
        edit->setValidator(
            new QRegularExpressionValidator(QRegularExpression(QStringLiteral("[0-9]*")), edit));
        edit->selectAll();
        auto* ok = new QPushButton(QStringLiteral("OK"), &dialog);
        ok->setGeometry(du.Rect(96, 50, 50, 14));
        ok->setDefault(true);
        auto* cancel = new QPushButton(QStringLiteral("Cancel"), &dialog);
        cancel->setGeometry(du.Rect(152, 50, 50, 14));
        QObject::connect(ok, &QPushButton::clicked, &dialog, &QDialog::accept);
        QObject::connect(cancel, &QPushButton::clicked, &dialog, &QDialog::reject);
        edit->setFocus();

        if (dialog.exec() != QDialog::Accepted) return 0;
        bool           parsed = false;
        const qulonglong value = edit->text().toULongLong(&parsed);
        if (!parsed || value < minimum || value > 0xFFFFFFFFull) return minimum;
        return static_cast<uint32_t>(value);
    }
};

}

REGISTER_SERVICE_AS(QtNumberPrompt, cerfcore::NumberPrompt);
