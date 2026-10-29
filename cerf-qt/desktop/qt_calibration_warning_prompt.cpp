#include "../calibration_warning_prompt.h"

#include "../qt_painter.h"
#include "qt_main_window.h"
#include "qt_theme.h"

#include "calibration_warning_body.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/instance_gate.h>
#include <cerfcore/host/customizations_editor.h>

#include <QDialog>
#include <QImage>
#include <QPainter>
#include <QPointer>
#include <QPushButton>
#include <QWidget>

namespace {

using Body   = cerffrontend::CalibrationWarningBody;
using Prompt = cerffrontend::CalibrationWarningPrompt;

class CalibrationBody : public QWidget {
public:
    CalibrationBody(cerfcore::CerfEmulator& emu, QWidget* parent) : QWidget(parent), gate_(emu) {}

    static cerffrontend::Rgb TextColor(const QWidget& w) {
        const QColor c = w.palette().color(QPalette::ButtonText);
        return cerffrontend::Rgb{static_cast<uint8_t>(c.red()), static_cast<uint8_t>(c.green()),
                                 static_cast<uint8_t>(c.blue())};
    }

protected:
    void paintEvent(QPaintEvent*) override {
        gate_.Run([this](cerfcore::CerfEmulator& emu) {
            QPainter   p(this);
            QtPainter  painter(emu, p);
            const bool dark = emu.Get<QtTheme>().IsDark();
            Body::Layout(painter, width(), true, dark, TextColor(*this));
        });
    }

private:
    cerfcore::InstanceGate gate_;
};

class QtCalibrationWarningPrompt : public cerffrontend::CalibrationWarningPrompt {
public:
    using cerffrontend::CalibrationWarningPrompt::CalibrationWarningPrompt;

    bool ShouldRegister() override { return emu_.Get<cerfcore::DeviceConfig>().guest_additions; }

    cerffrontend::CalibWarningChoice Show() override {
        if (open_) return cerffrontend::CalibWarningChoice::kDismissed;
        auto choice = cerffrontend::CalibWarningChoice::kDismissed;

        QImage    probe(1, 1, QImage::Format_RGB32);
        QPainter  probe_painter(&probe);
        QtPainter measure(emu_, probe_painter);
        const int body_h = Body::Layout(measure, Body::kClientW, false, false, {});
        probe_painter.end();

        QDialog dialog(emu_.Get<QtMainWindow>().Window());
        dialog.setWindowTitle(QString::fromUtf8(Prompt::kTitle));
        dialog.setFixedSize(Body::kClientW, body_h + Body::kButtonRow);
        auto* body = new CalibrationBody(emu_, &dialog);
        body->setGeometry(0, 0, Body::kClientW, body_h);

        const int by       = body_h + Body::kButtonTop;
        const int close_x  = Body::kClientW - Body::kMargin - Body::kCloseW;
        const int chres_x  = close_x - Body::kButtonGap - Body::kChangeResW;
        const int switch_x = chres_x - Body::kButtonGap - Body::kSwitchW;
        auto* sw = new QPushButton(QString::fromUtf8(Prompt::kSwitchLabel), &dialog);
        auto* cr = new QPushButton(QString::fromUtf8(Prompt::kChangeLabel), &dialog);
        auto* cl = new QPushButton(QString::fromUtf8(Prompt::kCloseLabel), &dialog);
        sw->setGeometry(switch_x, by, Body::kSwitchW, Body::kButtonH);
        cr->setGeometry(chres_x, by, Body::kChangeResW, Body::kButtonH);
        cl->setGeometry(close_x, by, Body::kCloseW, Body::kButtonH);
        sw->setDefault(true);

        QObject::connect(sw, &QPushButton::clicked, &dialog, gate_.Bind([&] {
                             choice = cerffrontend::CalibWarningChoice::kSwitchToStock;
                             dialog.accept();
                         }));
        QObject::connect(cr, &QPushButton::clicked, &dialog, gate_.Bind([&] {
                             if (emu_.Get<cerfcore::CustomizationsEditor>().Open(true)) dialog.accept();
                         }));
        QObject::connect(cl, &QPushButton::clicked, &dialog, gate_.Bind([&dialog] { dialog.reject(); }));

        open_ = &dialog;
        dialog.exec();
        open_ = nullptr;
        return choice;
    }

    void Dismiss() override {
        if (open_) open_->reject();
    }

private:
    const cerfcore::InstanceGate gate_{emu_};
    QPointer<QDialog>            open_;
};

}

REGISTER_SERVICE_AS(QtCalibrationWarningPrompt, cerffrontend::CalibrationWarningPrompt);
