#pragma once

#include "qt_frame_presenter.h"

#include <cerfcore/core/instance_gate.h>

#include "frame_view_item.h"
#include <QtQml/qqmlregistration.h>

#include <cstdint>
#include <memory>
#include <vector>

class ExternalDisplayView : public FrameViewItem {
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
    bool Capture(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h);

    cerffrontend::ViewportLayout& Layout() { return presenter_->Layout(); }

    int SurfaceWidth() const;
    int SurfaceHeight() const;

signals:
    void surfaceSizeChanged();

private:
    const FrameLayers* PresentLayers() override;

    std::unique_ptr<QtFramePresenter> presenter_;
    cerfcore::InstanceGate            gate_;
    int                               source_id_ = 0;
};
