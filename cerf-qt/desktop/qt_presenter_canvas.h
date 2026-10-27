#pragma once

#include "../qt_emulator_view.h"
#include "../qt_frame_presenter.h"

#include "../viewport_layout.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/frame_source.h>

#include <QWidget>

#include <cstdint>
#include <functional>
#include <memory>
#include <vector>

class QScrollBar;

class QtPresenterCanvas : public QWidget, public QtEmulatorView {
public:
    QtPresenterCanvas(cerfcore::CerfEmulator& emu, QWidget* parent, cerfcore::FrameSource& source,
                      uint32_t surf_w, uint32_t surf_h, int present_interval_ms,
                      std::unique_ptr<QtPresentHooks> hooks);

    uint32_t GuestSurfaceWidth() const override { return presenter_.Layout().SurfaceWidth(); }
    uint32_t GuestSurfaceHeight() const override { return presenter_.Layout().SurfaceHeight(); }
    int      ContentWidth() const { return presenter_.Layout().ContentWidth(); }
    int      ContentHeight() const { return presenter_.Layout().ContentHeight(); }
    void     SetGuestSurfaceSize(uint32_t w, uint32_t h) override;

    cerffrontend::ViewportMode Mode() const { return presenter_.Layout().Mode(); }
    int                        IntegerFactor() const { return presenter_.Layout().IntegerFactor(); }
    bool                       Antialias() const { return presenter_.Layout().Antialias(); }
    void                       SetViewportMode(cerffrontend::ViewportMode m);
    void                       SetIntegerScale(int factor);
    void                       SetAntialias(bool on);
    void                       SetFramebufferActive(bool active) override;
    void                       Repaint() override { update(); }

    bool CaptureSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) override {
        return presenter_.Capture(out, w, h);
    }
    void SetResizeListener(std::function<void()> listener) { on_resized_ = std::move(listener); }

    qreal Dpr() const { return devicePixelRatioF(); }
    void  VisibleSize(int& w, int& h) const;
    bool  MapToGuest(int x, int y, int& sx, int& sy) const { return presenter_.Layout().HostToGuest(x, y, sx, sy); }
    void  ClampToGuest(int& sx, int& sy) const { presenter_.Layout().ClampGuest(sx, sy); }

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void changeEvent(QEvent* event) override;

    cerfcore::CerfEmulator& emu_;

private:
    void Relayout();
    void UpdateScrollbars();
    void OnScroll(bool horizontal, int value);

    QtFramePresenter      presenter_;
    QScrollBar*           hbar_ = nullptr;
    QScrollBar*           vbar_ = nullptr;
    std::function<void()> on_resized_;
};
