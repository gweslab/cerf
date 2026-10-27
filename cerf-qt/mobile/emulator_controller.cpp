#include "emulator_controller.h"

#include "android_haptics.h"
#include "mobile_emulator_window.h"
#include "mobile_menu_presenter.h"

#include "../button_row.h"
#include "../host_virtual_keys.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QQuickWindow>
#include <QVariantMap>

namespace {

QString ArrowSymbol(const cerffrontend::RowButton& b) {
    if (b.kind != cerffrontend::RowButton::Kind::kKey || b.named) return {};
    switch (b.vk) {
        case cerffrontend::kVkLeft:  return QStringLiteral("arrow_back");
        case cerffrontend::kVkUp:    return QStringLiteral("arrow_upward");
        case cerffrontend::kVkRight: return QStringLiteral("arrow_forward");
        case cerffrontend::kVkDown:  return QStringLiteral("arrow_downward");
        default:                     return {};
    }
}

}

void EmulatorController::OpenGearMenu(qreal x, qreal y) {
    if (!emu_) return;
    emu_->Get<MobileMenuPresenter>().Show(emu_->Get<MobileEmulatorWindow>().GearMenu(), QPointF(x, y));
}

void EmulatorController::OpenPointerMenu(qreal x, qreal y) {
    if (!emu_) return;
    emu_->Get<MobileMenuPresenter>().Show(emu_->Get<MobileEmulatorWindow>().PointerMenu(), QPointF(x, y));
}

void EmulatorController::MenuPicked(int id) {
    QMetaObject::invokeMethod(
        this,
        [this, id] {
            if (emu_) emu_->Get<MobileMenuPresenter>().Pick(id);
        },
        Qt::QueuedConnection);
}

void EmulatorController::RequestClose() {
    if (!emu_) return;
    emu_->Get<MobileEmulatorWindow>().CloseRequested();
}

QVariantList EmulatorController::RowButtons() {
    if (!emu_) return {};
    const std::vector<cerffrontend::RowButton> buttons = emu_->Get<cerffrontend::ButtonRow>().Buttons();
    QVariantList                               out;
    for (size_t i = 0; i < buttons.size(); ++i) {
        const cerffrontend::RowButton& b = buttons[i];
        QVariantMap                    entry;
        entry["index"]      = static_cast<int>(i);
        entry["label"]      = QString::fromStdString(b.label);
        entry["symbol"]     = ArrowSymbol(b);
        entry["held"]       = b.held;
        entry["groupStart"] = b.group_start;
        out.append(entry);
    }
    return out;
}

int EmulatorController::RowHoldMs() const { return cerffrontend::ButtonRow::kHoldMs; }

void EmulatorController::PressRowButton(int index) { row_press_.Begin(index); }

void EmulatorController::ReleaseRowButton(int index) { row_press_.End(index); }

void EmulatorController::CancelRowButton(int index) { row_press_.Cancel(index); }

bool EmulatorController::HoldRowButton(int index) {
    if (!emu_) return false;
    row_press_.HandOver(index);
    if (!emu_->Get<cerffrontend::ButtonRow>().HoldAt(static_cast<size_t>(index))) return false;
    PerformLongPressHaptic(*emu_->Get<MobileEmulatorWindow>().Window());
    return true;
}

void EmulatorController::RowStep(StripPressDelay::Step step, int index) {
    if (!emu_) return;
    auto& row = emu_->Get<cerffrontend::ButtonRow>();
    switch (step) {
        case StripPressDelay::Step::kPress:   row.PressAt(static_cast<size_t>(index)); return;
        case StripPressDelay::Step::kRelease: row.ReleaseAt(static_cast<size_t>(index)); return;
        case StripPressDelay::Step::kCancel:  row.CancelPress(); return;
    }
}
