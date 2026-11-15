#pragma once

#include "overlay_item_model.h"

#include <QAbstractItemModel>
#include <QObject>
#include <QPointF>
#include <QRectF>
#include <QString>
#include <QUrl>
#include <QtQml/qqmlregistration.h>

#include <cstdint>

namespace cerfcore {
class CerfEmulator;
}

class CanvasTabView : public QObject {
    Q_OBJECT
    QML_ANONYMOUS
    Q_PROPERTY(bool bootShown READ BootShown NOTIFY bootShownChanged)
    Q_PROPERTY(bool consoleShown READ ConsoleShown NOTIFY consoleShownChanged)
    Q_PROPERTY(bool paused READ Paused NOTIFY pausedChanged)
    Q_PROPERTY(QString bootLabel READ BootLabel NOTIFY bootLabelChanged)
    Q_PROPERTY(int restartSerial READ RestartSerial NOTIFY restartSerialChanged)
    Q_PROPERTY(bool latched READ Latched NOTIFY latchedChanged)
    Q_PROPERTY(QString hwLine READ HwLine NOTIFY hwLineChanged)
    Q_PROPERTY(QAbstractItemModel* log READ Log CONSTANT)
    Q_PROPERTY(QUrl logo READ Logo CONSTANT)

public:
    explicit CanvasTabView(QObject* parent = nullptr);

    bool                BootShown() const { return boot_shown_; }
    bool                ConsoleShown() const { return console_shown_; }
    bool                Paused() const { return paused_; }
    QString             BootLabel() const { return boot_label_; }
    int                 RestartSerial() const { return restart_serial_; }
    bool                Latched() const { return latched_; }
    QString             HwLine() const { return hw_line_; }
    QAbstractItemModel* Log() { return &log_; }
    QUrl                Logo() const;

    Q_INVOKABLE void PlaceHwLine(QRectF hit);

    void Refresh(cerfcore::CerfEmulator& emu, QPointF scale);

signals:
    void bootShownChanged();
    void consoleShownChanged();
    void pausedChanged();
    void bootLabelChanged();
    void restartSerialChanged();
    void latchedChanged();
    void hwLineChanged();

private:
    template <typename T>
    void Publish(T& field, const T& value, void (CanvasTabView::*notify)()) {
        if (field == value) return;
        field = value;
        emit(this->*notify)();
    }

    OverlayItemModel log_;
    bool             boot_shown_     = false;
    bool             console_shown_  = false;
    bool             paused_         = false;
    QString          boot_label_;
    int              restart_serial_ = 0;
    bool             latched_        = false;
    QString          hw_line_;
    QRectF           hw_line_hit_;
};
