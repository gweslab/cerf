#include "qt_guest_cursor_cache.h"

#include "qt_guest_cursor_image.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_cursor.h>

REGISTER_SERVICE(QtGuestCursorCache);

bool QtGuestCursorCache::Refresh() {
    auto* cursor = emu_.TryGet<cerfcore::CerfVirtCursor>();
    if (!cursor) return false;
    const uint32_t seq = cursor->Seq();
    if (seq != seq_) {
        seq_ = seq;
        cerfcore::GuestCursorShape shape;
        if (cursor->GetShape(shape)) {
            known_   = true;
            visible_ = shape.visible;
            image_   = shape.visible ? GuestCursorImage(shape) : QImage();
            hotspot_ = QPoint(static_cast<int>(shape.xhot), static_cast<int>(shape.yhot));
            ++generation_;
        }
    }
    return known_;
}
