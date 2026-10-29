#include "../balloon_hint.h"

#include "qt_main_window.h"
#include "qt_status_bar.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QRect>
#include <QToolTip>
#include <QWidget>

namespace {

class QtBalloonHint : public cerffrontend::BalloonHint {
public:
    using cerffrontend::BalloonHint::BalloonHint;

    void ShowUnderWidget(const cerfcore::HostWidget* anchor, const std::string& text,
                         uint32_t hold_ms) override {
        QRect rc;
        Show(emu_.Get<QtMainWindow>().Bar().WidgetScreenRect(emu_, anchor, rc) ? &rc : nullptr, text,
             hold_ms);
    }

    void ShowUnderCaptureWidget(const std::string& text, uint32_t hold_ms) override {
        QRect rc;
        Show(emu_.Get<QtMainWindow>().Bar().CaptureWidgetScreenRect(emu_, rc) ? &rc : nullptr, text,
             hold_ms);
    }

private:
    void Show(const QRect* anchor, const std::string& text, uint32_t hold_ms) {
        QWidget* canvas = emu_.Get<QtMainWindow>().CanvasWidget();
        if (!canvas) return;
        QPoint p;
        if (anchor) {
            p = QPoint(anchor->center().x(), anchor->bottom() + 1);
        } else {
            p = canvas->mapToGlobal(QPoint(canvas->width() / 2, canvas->height() - kCanvasBottomGap));
        }
        QToolTip::showText(p, QString::fromStdString(text), canvas, QRect(),
                           static_cast<int>(hold_ms));
    }
};

}

REGISTER_SERVICE_AS(QtBalloonHint, cerffrontend::BalloonHint);
