#include "hud_nodes.h"

#include "host_key_name.h"
#include "hud_selection.h"
#include "pc_key_legend.h"
#include "qt_resource_paths.h"
#include "qt_rgb_color.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/hud_database.h>
#include <cerfcore/host/keyboard_map.h>
#include <cerfcore/host/machine_indicators.h>
#include <cerfcore/host/machine_object_tree.h>

#include <algorithm>
#include <cmath>
#include <string>
#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(HudNodes);

namespace {

using cerfcore::HudDpadShape;
using cerfcore::HudNode;

enum CanvasSide { kUp, kRight, kDown, kLeft };

constexpr int kKeyAbsent  = 0;
constexpr int kKeyShown   = 1;
constexpr int kKeyPressed = 2;

const QList<QByteArray> kRoles = {"kind",    "boxLeft", "boxTop", "boxWidth", "boxHeight", "label",
                                  "symbol",  "hint",    "down",   "latched",  "circle",    "arrows",
                                  "center",  "lamps",   "lampShape", "mono",     "keyUnit"};

constexpr std::pair<cerfcore::HudLampShape, const char*> kLampShapeNames[] = {
    {cerfcore::HudLampShape::kCircle, "circle"}, {cerfcore::HudLampShape::kDisc, "disc"}};

QString LampShapeName(cerfcore::HudLampShape shape) {
    for (const auto& [value, name] : kLampShapeNames)
        if (value == shape) return QString::fromLatin1(name);
    return QString();
}

QVariantMap LampRow(const cerfcore::LampState& state) {
    const auto rgb = [](cerfcore::ObjectRgb c) { return ToQColor(cerffrontend::Rgb{c.r, c.g, c.b}); };
    return {{QStringLiteral("lit"), state.lit},
            {QStringLiteral("color"), rgb(state.color)},
            {QStringLiteral("blinking"), state.blinking},
            {QStringLiteral("onMs"), static_cast<int>(state.blink_on_ms)},
            {QStringLiteral("offMs"), static_cast<int>(state.blink_off_ms)},
            {QStringLiteral("between"), state.between_blinks ? QVariant(rgb(*state.between_blinks)) : QVariant()}};
}

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
    row[QStringLiteral("lamps")]     = QVariantList();
    row[QStringLiteral("lampShape")] = QString();
    row[QStringLiteral("mono")]      = false;
    row[QStringLiteral("keyUnit")]   = 0.0;
    return row;
}

CanvasSide SideOf(FramePoint v) {
    if (std::abs(v.x) > std::abs(v.y)) return v.x > 0.0 ? kRight : kLeft;
    return v.y > 0.0 ? kDown : kUp;
}

cerfcore::HudFace LabelFace(std::string label) {
    cerfcore::HudFace face;
    face.label = std::move(label);
    return face;
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
    const cerfcore::KeyboardMap* map    = emu_.TryGet<cerfcore::KeyboardMap>();
    const uint8_t                layer  = map == nullptr ? 0 : HeldLayer(*map);
    const auto                   side   = [scale](const HudShown& shown) {
        return std::min(shown.canvas.w / scale.x(), shown.canvas.h / scale.y());
    };
    const double                 keycap = HudSmallest(controls.Shown(), HudIsKeycap, side);
    const double                 unit   = keycap > 0.0 ? keycap : HudSmallest(controls.Shown(), HudIsControl, side);
    for (const HudShown& shown : controls.Shown()) {
        if (shown.node->kind == HudNode::Kind::kButton)
            out.append(Button(shown, Face(shown.node->button, map, layer), Renamed(shown.node->button.keys, map),
                              scale, unit));
        else if (shown.node->kind == HudNode::Kind::kSticker)   out.append(Sticker("sticker", shown, scale));
        else if (shown.node->kind == HudNode::Kind::kIndicator) out.append(Sticker("indicator", shown, scale));
        else                                                     out.append(Dpad(shown, scale, unit));
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
    if (!button.face.lamp.object.empty()) return button.face;
    if (map != nullptr && layer != 0 && button.keys.size() == 1)
        if (const char* label = map->GuestLabel(button.keys[0], layer)) {
            for (const cerfcore::HudLayerFace& held : button.layer_faces)
                if (map->HeldLayer(held.held) == layer) return held.face;
            return LabelFace(label);
        }
    if (!button.face.label.empty() || !button.face.icon.empty()) return button.face;
    std::string label;
    for (uint8_t vk : button.keys) {
        const char* guest  = map == nullptr ? nullptr : map->GuestLabel(vk, 0);
        const char* legend = PcKeyLegend(vk);
        if (!label.empty()) label += '+';
        label += guest != nullptr ? std::string(guest) : legend != nullptr ? std::string(legend) : HostKeyName(vk);
    }
    return LabelFace(std::move(label));
}

void HudNodes::SetFace(QVariantMap& row, const cerfcore::HudFace& face) {
    if (!face.lamp.object.empty()) {
        row[QStringLiteral("lamps")]     = Lamps(face.lamp.object);
        row[QStringLiteral("lampShape")] = LampShapeName(face.lamp.shape);
    } else if (!face.display.empty()) {
        auto* display = dynamic_cast<cerfcore::MachineCharacterDisplay*>(
            emu_.Get<cerfcore::MachineObjectTree>().Find(face.display));
        row[QStringLiteral("label")] = display == nullptr ? QString() : QString::fromStdString(display->Characters());
        row[QStringLiteral("mono")]  = true;
    } else if (!face.icon.empty()) {
        row[QStringLiteral("symbol")] = SymbolIconUrl(QString::fromStdString(face.icon));
    } else {
        row[QStringLiteral("label")] = QString::fromStdString(face.label);
    }
}

QVariantList HudNodes::Lamps(const std::vector<std::string>& path) {
    auto&        tree = emu_.Get<cerfcore::MachineObjectTree>();
    auto*        lamp = dynamic_cast<cerfcore::MachineLamp*>(tree.Find(path));
    QVariantList out;
    if (lamp == nullptr) return out;
    out.append(LampRow(lamp->Lamp()));
    for (cerfcore::MachineObject* child : tree.Children(lamp))
        if (auto* element = dynamic_cast<cerfcore::MachineLamp*>(child)) out.append(LampRow(element->Lamp()));
    return out;
}

bool HudNodes::Renamed(const std::vector<uint8_t>& keys, const cerfcore::KeyboardMap* map) {
    if (map == nullptr) return false;
    return std::any_of(keys.begin(), keys.end(), [map](uint8_t vk) {
        const char* guest  = map->GuestLabel(vk, 0);
        const char* legend = PcKeyLegend(vk);
        return guest != nullptr && (legend == nullptr || !SameKeyName(guest, legend));
    });
}

QVariantMap HudNodes::Button(const HudShown& shown, const cerfcore::HudFace& face, bool renamed, QPointF scale,
                             double key_unit) {
    auto&                      controls = emu_.Get<HudControls>();
    const cerfcore::HudButton& button   = shown.node->button;
    QVariantMap                row      = Row("button", shown.canvas, scale);
    SetFace(row, face);
    row[QStringLiteral("keyUnit")] = key_unit;
    row[QStringLiteral("down")]    = controls.Pressed(shown.node) || controls.KeysDown(button.keys);
    row[QStringLiteral("latched")] = controls.Latched(shown.node);
    if (!controls.InsideCanvas()) {
        const std::string hint = KeyHint(button.keys);
        if (!hint.empty() && !SameKeyName(hint, face.label) && (!face.label.empty() || renamed))
            row[QStringLiteral("hint")] = QString::fromStdString(hint);
    }
    return row;
}

QVariantMap HudNodes::Sticker(const char* kind, const HudShown& shown, QPointF scale) {
    QVariantMap row = Row(kind, shown.canvas, scale);
    SetFace(row, shown.node->sticker);
    return row;
}

QVariantMap HudNodes::Dpad(const HudShown& shown, QPointF scale, double key_unit) {
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
    row[QStringLiteral("keyUnit")] = key_unit;
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
