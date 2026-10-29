#pragma once

#include "../qt_frame_presenter.h"

#include <cerfcore/core/instance_gate.h>

#include <QQuickPaintedItem>
#include <QtQml/qqmlregistration.h>

#include <cstdint>
#include <memory>

class ExternalDisplayView : public QQuickPaintedItem {
    Q_OBJECT
    QML_ELEMENT
    Q_PROPERTY(int surfaceWidth READ SurfaceWidth NOTIFY surfaceSizeChanged)
    Q_PROPERTY(int surfaceHeight READ SurfaceHeight NOTIFY surfaceSizeChanged)

public:
    explicit ExternalDisplayView(QQuickItem* parent = nullptr);
    ~ExternalDisplayView() override;

    void Attach(int source_id, cerfcore::CerfEmulator& emu, uint32_t surf_w, uint32_t surf_h);
    void Detach();
    void SetSurfaceSize(uint32_t w, uint32_t h);

    int SurfaceWidth() const;
    int SurfaceHeight() const;

    void paint(QPainter* painter) override;

signals:
    void surfaceSizeChanged();

private:
    std::unique_ptr<QtFramePresenter> presenter_;
    cerfcore::InstanceGate            gate_;
    int                               source_id_ = 0;
};
