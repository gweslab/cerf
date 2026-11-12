#pragma once

#include "content_window_state.h"
#include "viewport_menu.h"

#include "../external_display_container.h"
#include "../menu_source.h"
#include "../widget_menu_model.h"

#include <cerfcore/core/instance_gate.h>

#include <QObject>
#include <QPointer>
#include <QString>
#include <QStringList>
#include <QVariantList>

#include <cstdint>
#include <vector>

class ExternalDisplayView;
class QKeyEvent;
class QQuickWindow;

class ExternalDisplayWindow : public QObject,
                              public ExternalDisplayContainer,
                              public cerffrontend::ViewportMenuTarget,
                              public MenuSource {
    Q_OBJECT

public:
    ExternalDisplayWindow(cerfcore::CerfEmulator& emu, int source_id, const QString& title, uint32_t w, uint32_t h);
    ~ExternalDisplayWindow() override;

    void SetSurfaceSize(uint32_t w, uint32_t h) override;

    Q_INVOKABLE QStringList  MenuTitles() const override;
    Q_INVOKABLE QVariantList Menu(int index, QObject* menu) override;
    Q_INVOKABLE void         MenuPicked(QObject* menu, int id) override;
    Q_INVOKABLE void         Eject();

    cerffrontend::ViewportMode Mode() const override;
    int                        IntegerFactor() const override;
    bool                       Antialias() const override;
    void                       SetViewportMode(cerffrontend::ViewportMode m) override;
    void                       SetIntegerScale(int factor) override;
    void                       SetAntialias(bool on) override;
    bool                       IsFullscreen() const override { return chrome_.IsFullscreen(); }
    void                       ToggleFullscreen() override;
    void                       SaveScreenshot() override;
    void                       CopyScreenshot() override;
    void                       AfterModeChange(bool integer_scale) override;

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    void                                FitToSurface();
    void                                RouteKey(cerfcore::CerfEmulator& emu, const QKeyEvent& event, bool key_up);
    std::vector<cerffrontend::MenuItem> ViewItems(cerfcore::CerfEmulator& emu);

    cerfcore::InstanceGate         gate_;
    int                            source_id_;
    QString                        title_;
    QPointer<QQuickWindow>         window_;
    QPointer<ExternalDisplayView>  view_;
    ContentWindowState             chrome_;
    bool                           closing_ = false;
};
