#include "bar_widget_list.h"

#include "bar_widgets.h"
#include "qt_emulator_window.h"
#include "qt_menu_presenter.h"
#include "qt_resource_paths.h"
#include "qt_rgb_color.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/pointer_router.h>

#include <variant>

namespace {

constexpr int      kTickMs     = 100;
constexpr uint32_t kHintHoldMs = 3000;
constexpr int      kHintGap    = 96;

const QList<QByteArray> kRoles = {"kind",    "name",      "tooltip", "usable", "rxCount", "txCount", "source",
                                  "lamps",   "vibrate",   "cells",   "percent", "unplugged", "level", "failed",
                                  "folderOn"};

QVariantMap LampRow(const cerffrontend::LampLook& lamp) {
    return {{QStringLiteral("lit"), lamp.lit},
            {QStringLiteral("color"), ToQColor(lamp.color)},
            {QStringLiteral("blinking"), lamp.blinking},
            {QStringLiteral("onMs"), static_cast<int>(lamp.on_ms)},
            {QStringLiteral("offMs"), static_cast<int>(lamp.off_ms)},
            {QStringLiteral("between"), lamp.between ? QVariant(ToQColor(*lamp.between)) : QVariant()}};
}

QString Level(cerffrontend::BatteryLevel level) {
    switch (level) {
        case cerffrontend::BatteryLevel::kHigh: return QStringLiteral("high");
        case cerffrontend::BatteryLevel::kLow:  return QStringLiteral("low");
        case cerffrontend::BatteryLevel::kCritical: return QStringLiteral("critical");
    }
    return QStringLiteral("high");
}

struct IconRow {
    QVariantMap& row;

    void operator()(const cerffrontend::ResourceIcon& icon) const {
        row[QStringLiteral("kind")]   = QStringLiteral("resource");
        row[QStringLiteral("source")] = AssetImageUrl(QString::fromStdString(icon.name));
    }
    void operator()(const cerffrontend::ChipIcon&) const { row[QStringLiteral("kind")] = QStringLiteral("chip"); }
    void operator()(const cerffrontend::HardDiskIcon&) const { row[QStringLiteral("kind")] = QStringLiteral("disk"); }
    void operator()(const cerffrontend::LedIcon& icon) const {
        QVariantList lamps;
        for (const cerffrontend::LampLook& lamp : icon.lamps) lamps.append(LampRow(lamp));
        row[QStringLiteral("kind")]    = QStringLiteral("led");
        row[QStringLiteral("lamps")]   = lamps;
        row[QStringLiteral("vibrate")] = icon.vibrate;
    }
    void operator()(const cerffrontend::LedGridIcon& icon) const {
        QVariantList cells;
        for (const cerffrontend::LedGridCell& cell : icon.cells)
            cells.append(QVariantMap{{QStringLiteral("lit"), cell.lit}, {QStringLiteral("color"), ToQColor(cell.color)}});
        row[QStringLiteral("kind")]  = QStringLiteral("grid");
        row[QStringLiteral("cells")] = cells;
    }
    void operator()(const cerffrontend::PowerInputIcon& icon) const {
        row[QStringLiteral("kind")]   = QStringLiteral("power");
        row[QStringLiteral("failed")] = icon.failed;
    }
    void operator()(const cerffrontend::BatteryIcon& icon) const {
        row[QStringLiteral("kind")]      = QStringLiteral("battery");
        row[QStringLiteral("percent")]   = icon.fill_percent;
        row[QStringLiteral("unplugged")] = icon.on_battery;
        row[QStringLiteral("level")]     = Level(icon.level);
    }
    void operator()(const cerffrontend::FolderIcon& icon) const {
        row[QStringLiteral("kind")]     = QStringLiteral("folder");
        row[QStringLiteral("folderOn")] = icon.enabled;
    }
};

}

BarWidgetList::BarWidgetList(QObject* parent) : QObject(parent), items_(kRoles, this) {
    tick_.setInterval(kTickMs);
    QObject::connect(&tick_, &QTimer::timeout, this, [this] { Tick(); });
}

void BarWidgetList::Attach(cerfcore::CerfEmulator& emu) {
    gate_.Attach(emu);
    tick_.start();
    Tick();
}

void BarWidgetList::Detach() {
    tick_.stop();
    gate_ = cerfcore::InstanceGate();
    shown_.clear();
}

bool BarWidgetList::Shown(cerfcore::CerfEmulator& emu, const cerffrontend::BarWidget* widget) const {
    if (!strip_) return true;
    const cerffrontend::BarWidget* pointer =
        emu.Get<cerffrontend::BarWidgets>().ForObject(&emu.Get<cerfcore::PointerRouter>());
    return widget != pointer && widget->Group() != cerffrontend::BarGroup::InputCapture;
}

QVariantMap BarWidgetList::Row(const cerffrontend::BarWidget* widget) const {
    QVariantMap row;
    for (const QByteArray& role : kRoles) row.insert(QString::fromLatin1(role), QVariant());
    row[QStringLiteral("lamps")]   = QVariantList();
    row[QStringLiteral("cells")]   = QVariantList();
    row[QStringLiteral("name")]    = QString::fromStdString(widget->Name());
    row[QStringLiteral("tooltip")] = QString::fromStdString(widget->Tooltip());
    row[QStringLiteral("usable")]  = widget->IsEnabled();
    row[QStringLiteral("rxCount")] = static_cast<double>(widget->RxCount());
    row[QStringLiteral("txCount")] = static_cast<double>(widget->TxCount());
    std::visit(IconRow{row}, widget->Icon());
    return row;
}

void BarWidgetList::Tick() {
    gate_.Run([this](cerfcore::CerfEmulator& emu) {
        auto&                    widgets = emu.Get<cerffrontend::BarWidgets>();
        std::vector<ShownWidget> shown;
        QList<QVariantMap>       rows;
        for (cerffrontend::BarWidget* widget : widgets.Ordered()) {
            if (!Shown(emu, widget)) continue;
            const uint64_t id  = widgets.IdOf(widget);
            QRectF         box;
            for (const ShownWidget& previous : shown_)
                if (previous.id == id) box = previous.box;
            shown.push_back(ShownWidget{id, widget->Group() == cerffrontend::BarGroup::InputCapture, box});
            rows.append(Row(widget));
        }
        shown_ = std::move(shown);
        items_.Update(std::move(rows));
    });
}

void BarWidgetList::Activate(int row, QPointF scene_point, bool menu) {
    if (row < 0 || static_cast<size_t>(row) >= shown_.size()) return;
    const uint64_t id = shown_[static_cast<size_t>(row)].id;
    gate_.Run([&](cerfcore::CerfEmulator& emu) {
        RunWidget(emu, emu.Get<cerffrontend::BarWidgets>().Find(id), scene_point, menu);
    });
}

void BarWidgetList::RunWidget(cerfcore::CerfEmulator& emu, cerffrontend::BarWidget* widget, QPointF scene_point,
                              bool menu) {
    if (!menu && widget->PrimaryClick()) return;
    std::vector<cerffrontend::MenuItem> items = widget->Menu();
    if (widget->MenuIsOneAction() && items.size() == 1 && items[0].enabled && items[0].on_click &&
        items[0].submenu.empty()) {
        items[0].on_click();
        return;
    }
    if (strip_ && (menu || items.empty()))
        emu.Get<QtEmulatorWindow>().ShowHint(QString::fromStdString(widget->Tooltip()), kHintHoldMs, kHintGap);
    emu.Get<QtMenuPresenter>().Show(items, scene_point);
}

void BarWidgetList::PlaceWidget(int row, QRectF scene_rect) {
    if (row < 0 || static_cast<size_t>(row) >= shown_.size()) return;
    shown_[static_cast<size_t>(row)].box = scene_rect;
}

bool BarWidgetList::WidgetSceneRect(uint64_t widget_id, QRectF& out) const {
    for (const ShownWidget& shown : shown_) {
        if (shown.id != widget_id || shown.box.isEmpty()) continue;
        out = shown.box;
        return true;
    }
    return false;
}

bool BarWidgetList::CaptureWidgetSceneRect(QRectF& out) const {
    for (const ShownWidget& shown : shown_)
        if (shown.capture) return WidgetSceneRect(shown.id, out);
    return false;
}
