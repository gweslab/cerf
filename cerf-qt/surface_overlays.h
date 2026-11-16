#pragma once

#include "notification_overlay.h"
#include "overlay_item_model.h"
#include "pointer_overlay.h"

#include <QAbstractItemModel>
#include <QObject>
#include <QPointF>
#include <QRectF>
#include <QString>
#include <QVariantList>
#include <QtQml/qqmlregistration.h>

#include <vector>

namespace cerfcore {
class CerfEmulator;
}

namespace cerffrontend {
class ViewportLayout;
}

class SurfaceOverlays : public QObject {
    Q_OBJECT
    QML_ANONYMOUS
    Q_PROPERTY(QAbstractItemModel* hud READ Hud CONSTANT)
    Q_PROPERTY(QAbstractItemModel* cards READ Cards CONSTANT)
    Q_PROPERTY(QString uiFamily READ UiFamily NOTIFY fontsChanged)
    Q_PROPERTY(QString monoFamily READ MonoFamily NOTIFY fontsChanged)
    Q_PROPERTY(bool dimmed READ Dimmed NOTIFY dimmedChanged)
    Q_PROPERTY(QRectF canvas READ Canvas NOTIFY canvasChanged)
    Q_PROPERTY(QPointF pixelScale READ Scale NOTIFY pixelScaleChanged)
    Q_PROPERTY(bool arrowShown READ ArrowShown NOTIFY arrowChanged)
    Q_PROPERTY(QPointF arrowAt READ ArrowAt NOTIFY arrowChanged)

public:
    explicit SurfaceOverlays(QObject* parent = nullptr);

    QAbstractItemModel*  Hud() { return &hud_; }
    QAbstractItemModel*  Cards() { return &cards_; }
    QString              UiFamily() const { return ui_family_; }
    QString              MonoFamily() const { return mono_family_; }
    bool                 Dimmed() const { return dimmed_; }
    QRectF               Canvas() const { return canvas_; }
    const CursorPicture& Cursor() const { return cursor_; }
    QPointF              Scale() const { return scale_; }
    bool                 ArrowShown() const { return arrow_shown_; }
    QPointF              ArrowAt() const { return arrow_at_; }

    Q_INVOKABLE void PlaceCards(const QVariantList& placed);

    void ShowFonts(cerfcore::CerfEmulator& emu);
    void ShowCanvas(const cerffrontend::ViewportLayout& layout, QPointF scale);
    void Refresh(cerfcore::CerfEmulator& emu, const cerffrontend::ViewportLayout& layout, QPointF scale,
                 CursorPicture cursor);

signals:
    void fontsChanged();
    void dimmedChanged();
    void canvasChanged();
    void cursorChanged();
    void pixelScaleChanged();
    void arrowChanged();

private:
    OverlayItemModel                      hud_;
    OverlayItemModel                      cards_;
    std::vector<cerffrontend::PlacedCard> placed_;
    QString                               ui_family_;
    QString                               mono_family_;
    bool                                  dimmed_ = false;
    QRectF                                canvas_;
    CursorPicture                         cursor_;
    QPointF                               scale_{1.0, 1.0};
    bool                                  arrow_shown_ = false;
    QPointF                               arrow_at_;
};
