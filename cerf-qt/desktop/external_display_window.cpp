#include "external_display_window.h"

#include "global_menu_bar.h"
#include "qt_focus_policy.h"

#include "../cerfman/manager_engine.h"
#include "../external_display_sources.h"
#include "../external_display_view.h"
#include "../frontend_window.h"
#include "../host_key_binding.h"
#include "../host_virtual_keys.h"
#include "../native_menu_bar.h"
#include "../qt_menu_presenter.h"
#include "../qt_key_input.h"
#include "../screenshots.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QEvent>
#include <QKeyEvent>
#include <QMetaObject>
#include <QQuickWindow>
#include <QVariantMap>

#include <vector>

namespace {

constexpr int kMinWidth  = 160;
constexpr int kMinHeight = 120;

}

ExternalDisplayWindow::ExternalDisplayWindow(cerfcore::CerfEmulator& emu, int source_id, const QString& title,
                                             uint32_t w, uint32_t h)
    : gate_(emu), source_id_(source_id), title_(title) {
    window_ = qobject_cast<QQuickWindow*>(emu.Get<ManagerEngine>().Open(
        QStringLiteral("ExternalDisplayWindow"),
        QVariantMap{{QStringLiteral("title"), title}, {QStringLiteral("display"), QVariant::fromValue<QObject*>(this)}}));
    view_ = window_->property("view").value<ExternalDisplayView*>();
    window_->setMinimumSize(QSize(kMinWidth, kMinHeight));
    window_->installEventFilter(this);
    view_->Attach(source_id, emu, w, h);
    if (NativeMenuBar::Active()) new GlobalMenuBar(*window_, *this);
    emu.Get<QtFocusPolicy>().Show(*window_);
    FitToSurface();
    emu.Get<QtFocusPolicy>().Focus(*view_);
}

ExternalDisplayWindow::~ExternalDisplayWindow() {
    closing_ = true;
    if (view_) view_->Detach();
    delete window_.data();
}

void ExternalDisplayWindow::SetSurfaceSize(uint32_t w, uint32_t h) {
    if (w == 0 || h == 0 || !view_) return;
    view_->SetSurfaceSize(w, h);
    FitToSurface();
}

void ExternalDisplayWindow::FitToSurface() {
    const int content_w = view_->Layout().ContentWidth();
    const int content_h = view_->Layout().ContentHeight();
    if (content_w <= 0 || content_h <= 0) return;
    if (const std::optional<WindowFit> fit =
            chrome_.PlanFit(*window_, static_cast<uint32_t>(content_w), static_cast<uint32_t>(content_h)))
        chrome_.ApplyFit(*window_, *fit);
}

QStringList ExternalDisplayWindow::MenuTitles() const { return {tr("View")}; }

QVariantList ExternalDisplayWindow::Menu(int, QObject* menu) {
    QVariantList model;
    gate_.Run([this, menu, &model](cerfcore::CerfEmulator& emu) {
        model = emu.Get<QtMenuPresenter>().Build(menu, ViewItems(emu));
    });
    return model;
}

std::vector<cerffrontend::MenuItem> ExternalDisplayWindow::ViewItems(cerfcore::CerfEmulator& emu) {
    std::vector<cerffrontend::MenuItem> items;
    emu.Get<cerffrontend::ViewportMenu>().Append(items, *this, nullptr);
    return items;
}

void ExternalDisplayWindow::MenuPicked(QObject* menu, int id) {
    gate_.Run([menu, id](cerfcore::CerfEmulator& emu) { emu.Get<QtMenuPresenter>().Action(menu, id)(); });
}

void ExternalDisplayWindow::Eject() {
    gate_.Run([this](cerfcore::CerfEmulator& emu) {
        emu.Get<cerffrontend::FrontendWindow>().RunOnUiThread(
            [&sources = emu.Get<ExternalDisplaySources>(), id = source_id_] { sources.Eject(id); });
    });
}

cerffrontend::ViewportMode ExternalDisplayWindow::Mode() const { return view_->Layout().Mode(); }

int ExternalDisplayWindow::IntegerFactor() const { return view_->Layout().IntegerFactor(); }

void ExternalDisplayWindow::SetViewportMode(cerffrontend::ViewportMode m) {
    if (view_->Layout().SetMode(m)) view_->update();
}

void ExternalDisplayWindow::SetIntegerScale(int factor) {
    if (view_->Layout().SetIntegerScale(factor)) view_->update();
}

void ExternalDisplayWindow::ToggleFullscreen() {
    chrome_.ToggleFullscreen(*window_);
    if (chrome_.IsFullscreen())
        gate_.Run([this](cerfcore::CerfEmulator& emu) { emu.Get<QtFocusPolicy>().Raise(*window_); });
}

void ExternalDisplayWindow::SaveScreenshot() {
    std::vector<uint32_t> px;
    uint32_t              w = 0;
    uint32_t              h = 0;
    if (!view_->Capture(px, w, h)) return;
    gate_.Run([&](cerfcore::CerfEmulator& emu) {
        emu.Get<cerffrontend::Screenshots>().SavePixels(px, w, h, title_.toStdString());
    });
}

void ExternalDisplayWindow::CopyScreenshot() {
    std::vector<uint32_t> px;
    uint32_t              w = 0;
    uint32_t              h = 0;
    if (!view_->Capture(px, w, h)) return;
    gate_.Run([&](cerfcore::CerfEmulator& emu) { emu.Get<cerffrontend::Screenshots>().CopyPixels(px, w, h); });
}

void ExternalDisplayWindow::AfterModeChange(bool integer_scale) {
    if (integer_scale) FitToSurface();
}

bool ExternalDisplayWindow::eventFilter(QObject* watched, QEvent* event) {
    switch (event->type()) {
        case QEvent::Close:
            if (closing_) return false;
            event->ignore();
            QMetaObject::invokeMethod(window_.data(), "askEject");
            return true;
        case QEvent::KeyPress:
        case QEvent::KeyRelease: {
            const auto& key    = *static_cast<QKeyEvent*>(event);
            const bool  key_up = event->type() == QEvent::KeyRelease;
            gate_.Run([&](cerfcore::CerfEmulator& emu) { RouteKey(emu, key, key_up); });
            return false;
        }
        default:
            return QObject::eventFilter(watched, event);
    }
}

void ExternalDisplayWindow::RouteKey(cerfcore::CerfEmulator& emu, const QKeyEvent& event, bool key_up) {
    if (key_up && event.isAutoRepeat()) return;
    QtHostKey key;
    auto&     keys = emu.Get<QtKeyInput>();
    if (!keys.Translate(&event, key)) return;
    keys.ForEachTransition(key, key_up, [&](bool up) {
        keys.Note(key, up);
        if (!up && key.vk == cerffrontend::kVkF && emu.Get<cerffrontend::HostKeyBinding>().AllMembersDownNow())
            ToggleFullscreen();
    });
}
