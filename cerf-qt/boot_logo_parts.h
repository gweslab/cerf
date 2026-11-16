#pragma once

#include <QObject>
#include <QRectF>
#include <QSizeF>
#include <QString>
#include <QVariantList>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

class BootLogoParts : public QObject {
    Q_OBJECT
    QML_ANONYMOUS
    Q_PROPERTY(QVariantMap frame READ Frame CONSTANT)
    Q_PROPERTY(QVariantMap spinner READ Spinner CONSTANT)
    Q_PROPERTY(QVariantList plates READ Plates CONSTANT)
    Q_PROPERTY(QVariantList boxes READ Boxes CONSTANT)

public:
    explicit BootLogoParts(QObject* parent = nullptr);

    QVariantMap  Frame() const { return frame_; }
    QVariantMap  Spinner() const { return spinner_; }
    QVariantList Plates() const { return plates_; }
    QVariantList Boxes() const { return boxes_; }

    Q_INVOKABLE QString RegionSource(const QString& asset, const QSizeF& canvas_pixels, const QRectF& region) const;

private:
    QVariantMap  frame_;
    QVariantMap  spinner_;
    QVariantList plates_;
    QVariantList boxes_;
};
