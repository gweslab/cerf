#pragma once

#include "hud_controls.h"
#include "viewport_layout.h"

#include <cerfcore/core/service.h>

#include <QByteArray>
#include <QList>
#include <QPointF>
#include <QVariantMap>

#include <cstdint>
#include <string>
#include <vector>

namespace cerfcore {
class KeyboardMap;
}

namespace cerffrontend {

class HudNodes : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static QList<QByteArray> Roles();
    QList<QVariantMap>       Build(const ViewportLayout::Layout& frame, QPointF scale);

private:
    uint8_t                  HeldLayer(const cerfcore::KeyboardMap& map);
    static cerfcore::HudFace Face(const cerfcore::HudButton& button, const cerfcore::KeyboardMap* map, uint8_t layer);
    static bool              Renamed(const std::vector<uint8_t>& keys, const cerfcore::KeyboardMap* map);
    QVariantMap              Button(const HudShown& shown, const cerfcore::HudFace& face, bool renamed, QPointF scale);
    QVariantMap              Sticker(const HudShown& shown, QPointF scale);
    QVariantMap              Dpad(const HudShown& shown, QPointF scale);
    int                      KeyState(const std::vector<uint8_t>& keys) const;
    static std::string       KeyHint(const std::vector<uint8_t>& keys);
};

}
