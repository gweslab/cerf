#pragma once

#include <QImage>
#include <QQuickPaintedItem>
#include <QTimer>
#include <QtQml/qqmlregistration.h>

namespace cerfcore {
class CerfEmulator;
}

class MobileWidgetBar : public QQuickPaintedItem {
    Q_OBJECT
    QML_ELEMENT

public:
    explicit MobileWidgetBar(QQuickItem* parent = nullptr);

    void Attach(cerfcore::CerfEmulator& emu);
    void Detach();

    void paint(QPainter* painter) override;

    Q_INVOKABLE void Activate(qreal x, qreal y, bool menu);

private:
    void Run(qreal x, qreal y, bool menu);
    void Tick();
    int  UnitWidth() const;

    cerfcore::CerfEmulator* emu_ = nullptr;
    QTimer                  tick_;
    QImage                  image_;
};
