#pragma once

#include "../qt_emulator_window.h"
#include "../widget_menu_model.h"

#include <QPointer>
#include <QString>
#include <QVariant>
#include <QVariantMap>

#include <cstdint>
#include <functional>
#include <vector>

class EmulatorController;
class GuestSurface;
class MobileWidgetBar;
class QQuickItem;
class QQuickWindow;

class MobileEmulatorWindow : public QtEmulatorWindow {
public:
    using QtEmulatorWindow::QtEmulatorWindow;
    ~MobileEmulatorWindow() override;

    void OnShutdown() override;

    bool IsFullscreen() const override { return fullscreen_; }
    void ToggleFullscreen() override;
    void MatchGuestSize() override;
    void RefitIfFollowingGuest() override;
    void FitToResolution(uint32_t w, uint32_t h) override;

    void                                OpenWindow();
    void                                Raise();
    void                                ReturnToManager();
    std::vector<cerffrontend::MenuItem> GearMenu();
    std::vector<cerffrontend::MenuItem> PointerMenu();
    QQuickWindow*                       Window() const;
    QVariant    RunDialog(const QString& type_name, const QVariantMap& properties,
                          const std::function<void(QObject*)>& opened = {});
    void        ShowHint(const QString& text, uint32_t hold_ms, int bottom_gap);
    QQuickItem* CreateExternalDisplay();
    void        CloseDialogs();

private:
    void     MakeWindow();
    QObject* CreateDialog(const QString& type_name, const QVariantMap& properties);
    void     AdoptResolutionToScreen();

    QPointer<QQuickWindow>       window_;
    QPointer<GuestSurface>       surface_;
    QPointer<EmulatorController> controller_;
    QPointer<MobileWidgetBar>    widget_bar_;

    bool fullscreen_ = true;
};
