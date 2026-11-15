#include "hud_nodes.h"

#include "host_key_name.h"
#include "hud_selection.h"
#include "pc_key_legend.h"
#include "qt_resource_paths.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/hud_database.h>
#include <cerfcore/host/keyboard_map.h>

#include <algorithm>
#include <cmath>

namespace cerffrontend {

REGISTER_SERVICE(HudNodes);

namespace {

using cerfcore::HudDpadShape;
using cerfcore::HudNode;

enum CanvasSide { kUp, kRight, kDown, kLeft };

constexpr int kKeyAbsent  = 0;
constexpr int kKeyShown   = 1;
constexpr int kKeyPressed = 2;

const QList<QByteArray> kRoles = {"kind",  "boxLeft", "boxTop", "boxWidth", "boxHeight", "label", "symbol",
                                  "hint",  "down",    "latched", "circle",  "arrows",    "center"};

QVariantMap Row(const char* kind, const FrameRect& r, QPointF scale) {
    QVariantMap row;
    for (const QByteArray& role : kRoles) row.insert(QString::fromLatin1(role), QVariant());
    row[QStringLiteral("kind")]      = QString::fromLatin1(kind);
    row[QStringLiteral("boxLeft")]   = r.x / scale.x();
    row[QStringLiteral("boxTop")]    = r.y / scale.y();
    row[QStringLiteral("boxWidth")]  = r.w / scale.x();
    row[QStringLiteral("boxHeight")] = r.h / scale.y();
    row[QStringLiteral("label")]     = QString();
    row[QStringLiteral("symbol")]    = QString();
    row[QStringLiteral("hint")]      = QString();
    row[QStringLiteral("down")]      = false;
    row[QStringLiteral("latched")]   = false;
    row[QStringLiteral("circle")]    = false;
    row[QStringLiteral("arrows")]    = QVariantList{kKeyAbsent, kKeyAbsent, kKeyAbsent, kKeyAbsent};
    row[QStringLiteral("center")]    = kKeyAbsent;
    return row;
}

void SetFace(QVariantMap& row, const cerfcore::HudFace& face) {
    if (!face.icon.empty()) row[QStringLiteral("symbol")] = SymbolIconUrl(QString::fromStdString(face.icon));
    else                    row[QStringLiteral("label")]  = QString::fromStdString(face.label);
}

CanvasSide SideOf(FramePoint v) {
    if (std::abs(v.x) > std::abs(v.y)) return v.x > 0.0 ? kRight : kLeft;
    return v.y > 0.0 ? kDown : kUp;
}

}

QList<QByteArray> HudNodes::Roles() { return kRoles; }

QList<QVariantMap> HudNodes::Build(const ViewportLayout::Layout& frame, QPointF scale) {
    QList<QVariantMap>     out;
    auto&                  controls = emu_.Get<HudControls>();
    const cerfcore::DbHud* hud      = emu_.Get<HudSelection>().Active();
    if (hud == nullptr) return out;
    if (frame.dst_w <= 0 || frame.dst_h <= 0) {
        controls.Clear();
        return out;
    }
    controls.Place(*hud, frame);
    const std::vector<FrameRect>& bands = controls.Bands();
    const FrameRect               image = frame.Rect();
    if (std::any_of(bands.begin(), bands.end(), [&image](const FrameRect& band) { return band.Overlaps(image); }))
        for (const FrameRect& band : bands) out.append(Row("band", band, scale));
    for (const HudSeparator& s : controls.Separators()) {
        const FrameRect line{std::min(s.from.x, s.to.x), std::min(s.from.y, s.to.y), std::abs(s.to.x - s.from.x),
                             std::abs(s.to.y - s.from.y)};
        out.append(Row("separator", line, scale));
    }
    const cerfcore::KeyboardMap* map   = emu_.TryGet<cerfcore::KeyboardMap>();
    const uint8_t                layer = map == nullptr ? 0 : HeldLayer(*map);
    for (const HudShown& shown : controls.Shown()) {
        if (shown.node->kind == HudNode::Kind::kButton)
            out.append(Button(shown, Face(shown.node->button, map, layer), Renamed(shown.node->button.keys, map),
                              scale));
        else if (shown.node->kind == HudNode::Kind::kSticker) out.append(Sticker(shown, scale));
        else                                                   out.append(Dpad(shown, scale));
    }
    return out;
}

uint8_t HudNodes::HeldLayer(const cerfcore::KeyboardMap& map) {
    const auto& controls = emu_.Get<HudControls>();
    for (const cerfcore::KeyBinding& b : map.Bindings())
        if (b.layer == 0 && b.holds_layer != 0 && controls.KeyDown(b.vk)) return b.holds_layer;
    return 0;
}

cerfcore::HudFace HudNodes::Face(const cerfcore::HudButton& button, const cerfcore::KeyboardMap* map, uint8_t layer) {
    if (map != nullptr && layer != 0 && button.keys.size() == 1)
        if (const char* label = map->GuestLabel(button.keys[0], layer)) {
            for (const cerfcore::HudLayerFace& held : button.layer_faces)
                if (map->HeldLayer(held.held) == layer) return held.face;
            return {label, {}};
        }
    if (!button.face.label.empty() || !button.face.icon.empty()) return button.face;
    std::string label;
    for (uint8_t vk : button.keys) {
        const char* guest  = map == nullptr ? nullptr : map->GuestLabel(vk, 0);
        const char* legend = PcKeyLegend(vk);
        if (!label.empty()) label += '+';
        label += guest != nullptr ? std::string(guest) : legend != nullptr ? std::string(legend) : HostKeyName(vk);
    }
    return {label, {}};
}

bool HudNodes::Renamed(const std::vector<uint8_t>& keys, const cerfcore::KeyboardMap* map) {
    if (map == nullptr) return false;
    return std::any_of(keys.begin(), keys.end(), [map](uint8_t vk) {
        const char* guest  = map->GuestLabel(vk, 0);
        const char* legend = PcKeyLegend(vk);
        return guest != nullptr && (legend == nullptr || !SameKeyName(guest, legend));
    });
}

QVariantMap HudNodes::Button(const HudShown& shown, const cerfcore::HudFace& face, bool renamed, QPointF scale) {
    auto&                      controls = emu_.Get<HudControls>();
    const cerfcore::HudButton& button   = shown.node->button;
    QVariantMap                row      = Row("button", shown.canvas, scale);
    SetFace(row, face);
    row[QStringLiteral("down")]    = controls.Pressed(shown.node) || controls.KeysDown(button.keys);
    row[QStringLiteral("latched")] = controls.Latched(shown.node);
    if (!controls.InsideCanvas()) {
        const std::string hint = KeyHint(button.keys);
        if (!hint.empty() && !SameKeyName(hint, face.label) && (!face.label.empty() || renamed))
            row[QStringLiteral("hint")] = QString::fromStdString(hint);
    }
    return row;
}

QVariantMap HudNodes::Sticker(const HudShown& shown, QPointF scale) {
    QVariantMap row = Row("sticker", shown.canvas, scale);
    SetFace(row, shown.node->sticker);
    return row;
}

QVariantMap HudNodes::Dpad(const HudShown& shown, QPointF scale) {
    const cerfcore::HudDpad& dpad  = shown.node->dpad;
    const FramePlacement&    place = emu_.Get<HudControls>().Placement();
    const FrameRect&         dr    = shown.device;
    const FramePoint         c{dr.x + dr.w / 2.0, dr.y + dr.h / 2.0};
    const FramePoint         mid = place.ToCanvas(c);
    struct Side {
        const std::vector<uint8_t>& keys;
        FramePoint                  along;
    };
    const Side   sides[] = {{dpad.up, {0.0, -1.0}}, {dpad.down, {0.0, 1.0}}, {dpad.left, {-1.0, 0.0}},
                            {dpad.right, {1.0, 0.0}}};
    QVariantList arrows{kKeyAbsent, kKeyAbsent, kKeyAbsent, kKeyAbsent};
    for (const Side& s : sides) {
        const FramePoint tip = place.ToCanvas(FramePoint{c.x + s.along.x, c.y + s.along.y});
        arrows[SideOf(FramePoint{tip.x - mid.x, tip.y - mid.y})] = KeyState(s.keys);
    }
    QVariantMap row                = Row("dpad", shown.canvas, scale);
    row[QStringLiteral("circle")]  = dpad.shape == HudDpadShape::kCircle;
    row[QStringLiteral("arrows")]  = arrows;
    row[QStringLiteral("center")]  = KeyState(dpad.center);
    return row;
}

int HudNodes::KeyState(const std::vector<uint8_t>& keys) const {
    if (keys.empty()) return kKeyAbsent;
    return emu_.Get<HudControls>().KeysDown(keys) ? kKeyPressed : kKeyShown;
}

std::string HudNodes::KeyHint(const std::vector<uint8_t>& keys) {
    std::string out;
    for (uint8_t vk : keys) {
        const char* legend = PcKeyLegend(vk);
        if (legend == nullptr) return std::string();
        if (!out.empty()) out += '+';
        out += legend;
    }
    return out;
}

}
