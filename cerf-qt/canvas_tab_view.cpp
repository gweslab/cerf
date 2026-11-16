#include "canvas_tab_view.h"

#include "boot_screen.h"
#include "canvas_tabs.h"
#include "hw_screen_log.h"
#include "qt_resource_paths.h"
#include "resource_paths_text.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/emulation_pause.h>
#include <cerfcore/host/hw_screen.h>

CanvasTabView::CanvasTabView(QObject* parent)
    : QObject(parent), log_(cerffrontend::HwScreenLog::Roles(), this), boot_logo_(this) {}

QUrl CanvasTabView::Logo() const { return QUrl(AssetImageUrl(QStringLiteral(CERF_LOGO_ASSET))); }

void CanvasTabView::PlaceHwLine(QRectF hit) { hw_line_hit_ = hit; }

void CanvasTabView::Refresh(cerfcore::CerfEmulator& emu, QPointF scale) {
    const cerfcore::CanvasTab tab  = emu.Get<cerffrontend::CanvasTabs>().Current();
    auto&                     boot = emu.Get<cerffrontend::BootScreen>();
    const bool                boot_shown    = tab == cerfcore::CanvasTab::Boot;
    const bool                console_shown = tab == cerfcore::CanvasTab::Hw;
    const bool                paused        = emu.Get<cerfcore::EmulationPause>().IsPaused();
    const QString             label         = QString::fromStdString(boot.Label());
    const int                 serial        = static_cast<int>(boot.RestartSerial());
    const bool                latched       = boot.Latched();
    const QString line = boot_shown ? QString::fromStdString(emu.Get<cerfcore::HwScreen>().LastLine()) : hw_line_;
    if (auto& log = emu.Get<cerffrontend::HwScreenLog>(); console_shown && log.Rebuild()) log_.Update(log.Lines());
    boot.SetHwLineHit(boot_shown && !line.isEmpty() ? hw_line_hit_ : QRectF(), scale);
    Publish(paused_, paused, &CanvasTabView::pausedChanged);
    Publish(boot_label_, label, &CanvasTabView::bootLabelChanged);
    Publish(latched_, latched, &CanvasTabView::latchedChanged);
    Publish(restart_serial_, serial, &CanvasTabView::restartSerialChanged);
    Publish(hw_line_, line, &CanvasTabView::hwLineChanged);
    Publish(console_shown_, console_shown, &CanvasTabView::consoleShownChanged);
    Publish(boot_shown_, boot_shown, &CanvasTabView::bootShownChanged);
}
