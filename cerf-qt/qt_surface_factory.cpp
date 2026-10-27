#include "surface_factory.h"

#include "qt_painter.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QImage>
#include <QPainter>

#include <algorithm>
#include <memory>

namespace {

class QtOffscreenSurface final : public cerffrontend::OffscreenSurface {
public:
    QtOffscreenSurface(cerfcore::CerfEmulator& emu, int width, int height)
        : image_(std::max(width, 1), std::max(height, 1), QImage::Format_RGB32) {
        image_.fill(0u);
        bits_ = reinterpret_cast<uint32_t*>(image_.bits());
        painter_.begin(&image_);
        qt_painter_ = std::make_unique<QtPainter>(emu, painter_);
    }

    ~QtOffscreenSurface() override { painter_.end(); }

    QtOffscreenSurface(const QtOffscreenSurface&)            = delete;
    QtOffscreenSurface& operator=(const QtOffscreenSurface&) = delete;

    uint32_t*              Bits() override { return bits_; }
    int                    Width() const override { return image_.width(); }
    int                    Height() const override { return image_.height(); }
    cerffrontend::Painter& Paint() override { return *qt_painter_; }

    void Flush() override {
        painter_.end();
        painter_.begin(&image_);
    }

private:
    QImage                     image_;
    uint32_t*                  bits_ = nullptr;
    QPainter                   painter_;
    std::unique_ptr<QtPainter> qt_painter_;
};

class QtSurfaceFactory : public cerffrontend::SurfaceFactory {
public:
    using cerffrontend::SurfaceFactory::SurfaceFactory;

    std::unique_ptr<cerffrontend::OffscreenSurface> Create(int width, int height) override {
        return std::make_unique<QtOffscreenSurface>(emu_, width, height);
    }
};

}

REGISTER_SERVICE_AS(QtSurfaceFactory, cerffrontend::SurfaceFactory);
