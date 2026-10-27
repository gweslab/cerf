#pragma once

#include <cerfcore/core/service.h>

#include <QImage>
#include <QPoint>

#include <cstdint>

class QtGuestCursorCache : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool Refresh();

    bool          Drawable() const { return visible_ && !image_.isNull(); }
    const QImage& Image() const { return image_; }
    QPoint        Hotspot() const { return hotspot_; }
    uint32_t      Generation() const { return generation_; }

private:
    QImage   image_;
    QPoint   hotspot_;
    uint32_t seq_        = 0;
    uint32_t generation_ = 0;
    bool     known_      = false;
    bool     visible_    = false;
};
