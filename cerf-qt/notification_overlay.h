#pragma once

#include <cerfcore/core/service.h>
#include <cerfcore/host/notification_stack.h>

#include <QByteArray>
#include <QList>
#include <QPointF>
#include <QRectF>
#include <QVariantMap>

#include <cstdint>
#include <vector>

namespace cerffrontend {

struct PlacedCard {
    uint32_t id = 0;
    QRectF   rect;
};

class NotificationOverlay : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static QList<QByteArray> Roles();
    const QList<QVariantMap>& Cards();
    void                      SetPlaced(std::vector<PlacedCard> placed, QPointF scale);
    bool                      HitTest(int x, int y, uint32_t& id) const;

private:
    std::vector<cerfcore::NotificationCard> cards_;
    QList<QVariantMap>                      rows_;
    uint64_t                                gen_ = ~0ull;
    std::vector<PlacedCard>                 placed_;
    QPointF                                 scale_{1.0, 1.0};
};

}
