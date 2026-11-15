#include "balloon_hint.h"

#include "bar_widget_list.h"
#include "bar_widgets.h"
#include "qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QRectF>
#include <QString>

namespace {

class QtBalloonHint : public cerffrontend::BalloonHint {
public:
    using cerffrontend::BalloonHint::BalloonHint;

    void ShowUnderWidget(const cerffrontend::BarWidget* anchor, const std::string& text, uint32_t hold_ms) override {
        QRectF         box;
        BarWidgetList* bar = emu_.Get<QtEmulatorWindow>().StatusBar();
        const bool     found =
            bar != nullptr && bar->WidgetSceneRect(emu_.Get<cerffrontend::BarWidgets>().IdOf(anchor), box);
        Show(found ? &box : nullptr, text, hold_ms);
    }

    void ShowUnderCaptureWidget(const std::string& text, uint32_t hold_ms) override {
        QRectF         box;
        BarWidgetList* bar   = emu_.Get<QtEmulatorWindow>().StatusBar();
        const bool     found = bar != nullptr && bar->CaptureWidgetSceneRect(box);
        Show(found ? &box : nullptr, text, hold_ms);
    }

private:
    void Show(const QRectF* anchor, const std::string& text, uint32_t hold_ms) {
        auto&         window = emu_.Get<QtEmulatorWindow>();
        const QString shown  = QString::fromStdString(text);
        if (anchor) window.ShowHintAt(shown, hold_ms, *anchor);
        else        window.ShowHint(shown, hold_ms, kCanvasBottomGap);
    }
};

}

REGISTER_SERVICE_AS(QtBalloonHint, cerffrontend::BalloonHint);
