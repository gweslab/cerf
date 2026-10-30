#pragma once

#include "../qt_emulator_view.h"
#include "../qt_frame_presenter.h"

#include "../viewport_layout.h"

#include <cerfcore/core/instance_gate.h>

#include <QWidget>

#include <cstdint>
#include <memory>
#include <vector>

class QScrollBar;

class QtPresenterCanvas : public QWidget, public QtEmulatorView {
public:
    QtPresenterCanvas(cerfcore::CerfEmulator& emu, QWidget* parent, uint32_t surf_w, uint32_t surf_h,
                      int present_interval_ms);

    uint32_t GuestSurfaceWidth() const override { return presenter_.Layout().SurfaceWidth(); }
    uint32_t GuestSurfaceHeight() const override { return presenter_.Layout().SurfaceHeight(); }
    int      ContentWidth() const { return presenter_.Layout().ContentWidth(); }
    int      ContentHeight() const { return presenter_.Layout().ContentHeight(); }
    void     ContentFor(uint32_t surface_w, uint32_t surface_h, int& content_w, int& content_h) const {
        presenter_.Layout().ContentFor(surface_w, surface_h, content_w, content_h);
    }
    void SurfaceFor(int content_w, int content_h, uint32_t& surface_w, uint32_t& surface_h) const {
        presenter_.Layout().SurfaceFor(content_w, content_h, surface_w, surface_h);
    }
    void     SetGuestSurfaceSize(uint32_t w, uint32_t h) override;
    void     SetPresentation(const cerffrontend::ViewPresentation& presentation) override;

    cerffrontend::ViewportMode Mode() const { return presenter_.Layout().Mode(); }
    int                        IntegerFactor() const { return presenter_.Layout().IntegerFactor(); }
    bool                       Antialias() const { return presenter_.Layout().Antialias(); }
    void                       SetViewportMode(cerffrontend::ViewportMode m);
    void                       SetIntegerScale(int factor);
    void                       SetAntialias(bool on);
    void                       SetFramebufferActive(bool active) override;
    void                       Repaint() override { update(); }

    bool CaptureSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) override;

    qreal Dpr() const { return devicePixelRatioF(); }
    void  VisibleSize(int& w, int& h) const;
    bool  MapToGuest(int x, int y, int& sx, int& sy) const { return presenter_.Layout().HostToGuest(x, y, sx, sy); }
    void  GuestPixelScale(double& sx, double& sy) const { presenter_.Layout().GuestPixelScale(sx, sy); }
    int   Quarter() const { return presenter_.Layout().Presentation().quarter & 3; }
    void  ClampToGuest(int& sx, int& sy) const { presenter_.Layout().ClampGuest(sx, sy); }

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void changeEvent(QEvent* event) override;

    void SetPresentHooks(std::unique_ptr<QtPresentHooks> hooks) { presenter_.SetHooks(std::move(hooks)); }

    virtual cerfcore::FrameSource& Source(cerfcore::CerfEmulator& emu) = 0;

    cerfcore::InstanceGate gate_;

private:
    void Relayout();
    void UpdateScrollbars();
    void OnScroll(bool horizontal, int value);

    QtFramePresenter presenter_;
    QScrollBar*      hbar_ = nullptr;
    QScrollBar*      vbar_ = nullptr;
};
