#pragma once

#include <cerfcore/core/service.h>

#include <QCursor>

#include <cstdint>

struct QtGuestCursorLook {
    int   scale_x = 1;
    int   scale_y = 1;
    int   quarter = 0;
    qreal dpr     = 1.0;

    bool operator==(const QtGuestCursorLook&) const = default;
};

class QtGuestCursor : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    QCursor Resolve(const QtGuestCursorLook& look, bool& active);

private:
    QCursor           built_{Qt::BlankCursor};
    uint32_t          built_generation_ = 0;
    QtGuestCursorLook built_look_;
};
