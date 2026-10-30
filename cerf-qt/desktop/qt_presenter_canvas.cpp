#include "qt_presenter_canvas.h"

#include "../qt_device_pixels.h"

#include <QEvent>
#include <QPainter>
#include <QScrollBar>
#include <QSignalBlocker>

#include <algorithm>

QtPresenterCanvas::QtPresenterCanvas(cerfcore::CerfEmulator& emu, QWidget* parent, uint32_t surf_w,
                                     uint32_t surf_h, int present_interval_ms)
    : QWidget(parent), gate_(emu), presenter_(std::make_unique<QtPresentHooks>(), surf_w, surf_h, Qt::black) {
    setFocusPolicy(Qt::StrongFocus);
    setMouseTracking(true);
    setAttribute(Qt::WA_OpaquePaintEvent);
    hbar_ = new QScrollBar(Qt::Horizontal, this);
    vbar_ = new QScrollBar(Qt::Vertical, this);
    hbar_->hide();
    vbar_->hide();
    hbar_->setSingleStep(cerffrontend::ViewportLayout::kScrollLineStep);
    vbar_->setSingleStep(cerffrontend::ViewportLayout::kScrollLineStep);
    QObject::connect(hbar_, &QScrollBar::valueChanged, this, [this](int v) { OnScroll(true, v); });
    QObject::connect(vbar_, &QScrollBar::valueChanged, this, [this](int v) { OnScroll(false, v); });

    UpdateScrollbars();
    update();
    presenter_.StartRepaints(present_interval_ms, [this] { update(); });
}

void QtPresenterCanvas::SetGuestSurfaceSize(uint32_t w, uint32_t h) {
    if (!presenter_.SetGuestSurfaceSize(w, h)) return;
    UpdateScrollbars();
    update();
}

void QtPresenterCanvas::SetPresentation(const cerffrontend::ViewPresentation& presentation) {
    if (!presenter_.Layout().SetPresentation(presentation)) return;
    UpdateScrollbars();
    update();
}

void QtPresenterCanvas::SetViewportMode(cerffrontend::ViewportMode m) {
    if (!presenter_.Layout().SetMode(m)) return;
    UpdateScrollbars();
    update();
}

void QtPresenterCanvas::SetIntegerScale(int factor) {
    if (!presenter_.Layout().SetIntegerScale(factor)) return;
    UpdateScrollbars();
    update();
}

void QtPresenterCanvas::SetAntialias(bool on) {
    if (presenter_.Layout().SetAntialias(on)) update();
}

void QtPresenterCanvas::SetFramebufferActive(bool active) {
    if (!presenter_.Layout().SetActive(active)) return;
    UpdateScrollbars();
    update();
}

void QtPresenterCanvas::paintEvent(QPaintEvent*) {
    gate_.Run([this](cerfcore::CerfEmulator& emu) {
        int client_w = 0, client_h = 0;
        VisibleSize(client_w, client_h);
        QPainter p(this);
        presenter_.DrawTo(emu, Source(emu), p, client_w, client_h, Dpr());
    });
}

bool QtPresenterCanvas::CaptureSurface(std::vector<uint32_t>& out, uint32_t& w, uint32_t& h) {
    bool captured = false;
    gate_.Run([&](cerfcore::CerfEmulator& emu) { captured = presenter_.Capture(Source(emu), out, w, h); });
    return captured;
}

void QtPresenterCanvas::resizeEvent(QResizeEvent*) { Relayout(); }

void QtPresenterCanvas::changeEvent(QEvent* event) {
    if (event->type() == QEvent::DevicePixelRatioChange) {
        Relayout();
        update();
    }
    QWidget::changeEvent(event);
}

void QtPresenterCanvas::Relayout() {
    const QSize canvas = DeviceCanvasSize(width(), height(), Dpr());
    presenter_.SetCanvasSize(canvas.width(), canvas.height());
    UpdateScrollbars();
}

void QtPresenterCanvas::UpdateScrollbars() {
    const cerffrontend::ViewportLayout::Scroll s = presenter_.Layout().UpdateScroll();
    const int            thick_v = vbar_->sizeHint().width();
    const int            thick_h = hbar_->sizeHint().height();
    const QSignalBlocker block_h(hbar_);
    const QSignalBlocker block_v(vbar_);
    hbar_->setVisible(s.horizontal);
    vbar_->setVisible(s.vertical);
    if (s.horizontal) {
        hbar_->setGeometry(0, height() - thick_h, width() - (s.vertical ? thick_v : 0), thick_h);
        hbar_->setRange(0, s.content_w - s.page_w);
        hbar_->setPageStep(s.page_w);
        hbar_->setValue(s.pos_x);
    }
    if (s.vertical) {
        vbar_->setGeometry(width() - thick_v, 0, thick_v, height() - (s.horizontal ? thick_h : 0));
        vbar_->setRange(0, s.content_h - s.page_h);
        vbar_->setPageStep(s.page_h);
        vbar_->setValue(s.pos_y);
    }
}

void QtPresenterCanvas::OnScroll(bool horizontal, int value) {
    presenter_.Layout().ScrollTo(horizontal, value);
    QScrollBar*          bar = horizontal ? hbar_ : vbar_;
    const QSignalBlocker block(bar);
    bar->setValue(presenter_.Layout().ScrollPos(horizontal));
    update();
}

void QtPresenterCanvas::VisibleSize(int& w, int& h) const {
    const qreal dpr = Dpr();
    w = DeviceExtent(width() - (vbar_->isVisible() ? vbar_->width() : 0), dpr);
    h = DeviceExtent(height() - (hbar_->isVisible() ? hbar_->height() : 0), dpr);
}
