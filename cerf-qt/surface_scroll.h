#pragma once

#include "viewport_layout.h"

#include <QObject>
#include <QtQml/qqmlregistration.h>

class SurfaceScroll : public QObject {
    Q_OBJECT
    QML_ANONYMOUS
    Q_PROPERTY(bool horizontal READ Horizontal NOTIFY changed)
    Q_PROPERTY(bool vertical READ Vertical NOTIFY changed)
    Q_PROPERTY(qreal horizontalSize READ HorizontalSize NOTIFY changed)
    Q_PROPERTY(qreal verticalSize READ VerticalSize NOTIFY changed)
    Q_PROPERTY(qreal horizontalPosition READ HorizontalPosition NOTIFY changed)
    Q_PROPERTY(qreal verticalPosition READ VerticalPosition NOTIFY changed)

public:
    void Bind(cerffrontend::ViewportLayout* layout);
    void Refresh();

    bool  Horizontal() const { return scroll_.horizontal; }
    bool  Vertical() const { return scroll_.vertical; }
    qreal HorizontalSize() const;
    qreal VerticalSize() const;
    qreal HorizontalPosition() const;
    qreal VerticalPosition() const;

    Q_INVOKABLE void ScrollTo(bool horizontal, qreal position);

signals:
    void changed();
    void scrolled();

private:
    static qreal Fraction(int part, int whole);

    cerffrontend::ViewportLayout*        layout_ = nullptr;
    cerffrontend::ViewportLayout::Scroll scroll_;
};
