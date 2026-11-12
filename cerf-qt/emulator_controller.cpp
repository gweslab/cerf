#include "emulator_controller.h"

#include "emulator_window_host.h"
#include "host_haptics.h"
#include "qt_emulator_window.h"
#include "qt_menu_presenter.h"

#include "button_row.h"
#include "host_virtual_keys.h"
#include "hud_selection.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QQuickWindow>
#include <QVariantMap>

namespace {

QString ArrowSymbol(const cerffrontend::RowButton& b) {
    if (b.named) return {};
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
    gate_.Run([x, y](cerfcore::CerfEmulator& emu) {
        emu.Get<QtMenuPresenter>().Show(emu.Get<QtEmulatorWindow>().GearMenu(), QPointF(x, y));
    });
}

void EmulatorController::OpenPointerMenu(qreal x, qreal y) {
    gate_.Run([x, y](cerfcore::CerfEmulator& emu) {
        emu.Get<QtMenuPresenter>().Show(emu.Get<QtEmulatorWindow>().PointerMenu(), QPointF(x, y));
    });
}

void EmulatorController::MenuPicked(QObject* menu, int id) {
    std::function<void()> action;
    gate_.Run([&action, menu, id](cerfcore::CerfEmulator& emu) { action = emu.Get<QtMenuPresenter>().Action(menu, id); });
    QMetaObject::invokeMethod(
        this, [this, action] { gate_.Run([&action](cerfcore::CerfEmulator&) { action(); }); }, Qt::QueuedConnection);
}

void EmulatorController::MenuClosing() {
    gate_.Run([](cerfcore::CerfEmulator& emu) { emu.Get<QtEmulatorWindow>().MenuClosing(); });
}

void EmulatorController::RequestClose() {
    gate_.Run([](cerfcore::CerfEmulator& emu) { emu.Get<QtEmulatorWindow>().CloseRequested(); });
}

QVariantList EmulatorController::RowButtons(bool keyboard_open) {
    QVariantList out;
    gate_.Run([&out, keyboard_open](cerfcore::CerfEmulator& emu) {
        auto& row = emu.Get<cerffrontend::ButtonRow>();
        row.SetKeysShown(keyboard_open);
        const std::vector<cerffrontend::RowButton> buttons = row.Buttons();
        for (size_t i = 0; i < buttons.size(); ++i) {
            const cerffrontend::RowButton& b = buttons[i];
            QVariantMap                    entry;
            entry["index"]      = static_cast<int>(i);
            entry["label"]      = QString::fromStdString(b.label);
            entry["symbol"]     = ArrowSymbol(b);
            entry["held"]       = b.held;
            out.append(entry);
        }
    });
    return out;
}

int EmulatorController::RowHoldMs() const { return cerffrontend::ButtonRow::kHoldMs; }

bool EmulatorController::HudAvailable() const {
    bool available = false;
    gate_.Run([&available](cerfcore::CerfEmulator& emu) {
        available = emu.Get<cerffrontend::HudSelection>().CanShow();
    });
    return available;
}

bool EmulatorController::HudShown() const {
    bool shown = false;
    gate_.Run([&shown](cerfcore::CerfEmulator& emu) { shown = emu.Get<cerffrontend::HudSelection>().Shown(); });
    return shown;
}

void EmulatorController::ToggleHud() {
    gate_.Run([](cerfcore::CerfEmulator& emu) { emu.Get<cerffrontend::HudSelection>().Toggle(); });
}

QStringList EmulatorController::MenuTitles() const {
    QStringList titles;
    gate_.Run([&titles](cerfcore::CerfEmulator& emu) {
        for (const std::string& title : emu.Get<EmulatorWindowHost>().MenuTitles())
            titles.append(QString::fromStdString(title));
    });
    return titles;
}

QVariantList EmulatorController::Menu(int index, QObject* menu) {
    QVariantList model;
    gate_.Run([index, menu, &model](cerfcore::CerfEmulator& emu) {
        model = emu.Get<QtMenuPresenter>().Build(menu, emu.Get<EmulatorWindowHost>().Menu(index));
    });
    return model;
}

void EmulatorController::RefitWindow() {
    gate_.Run([](cerfcore::CerfEmulator& emu) { emu.Get<EmulatorWindowHost>().RefitIfFollowingGuest(); });
}

void EmulatorController::PressRowButton(int index) { row_press_.Begin(index); }

void EmulatorController::ReleaseRowButton(int index) { row_press_.End(index); }

void EmulatorController::CancelRowButton(int index) { row_press_.Cancel(index); }

bool EmulatorController::HoldRowButton(int index) {
    if (!gate_.Attached()) return false;
    row_press_.HandOver(index);
    bool held = false;
    gate_.Run([index, &held](cerfcore::CerfEmulator& emu) {
        held = emu.Get<cerffrontend::ButtonRow>().HoldAt(static_cast<size_t>(index));
        if (held) PerformLongPressHaptic(*emu.Get<QtEmulatorWindow>().Window());
    });
    return held;
}

void EmulatorController::OnStripStep(StripPressDelay::Step step, int index) {
    gate_.Run([step, index](cerfcore::CerfEmulator& emu) {
        auto& row = emu.Get<cerffrontend::ButtonRow>();
        switch (step) {
            case StripPressDelay::Step::kPress:   row.PressAt(static_cast<size_t>(index)); return;
            case StripPressDelay::Step::kRelease: row.ReleaseAt(static_cast<size_t>(index)); return;
            case StripPressDelay::Step::kCancel:  row.CancelPress(); return;
        }
    });
}
