#include "status_bar.h"

#include "widget_icon_painter.h"
#include "widget_menu_builder.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/host_widget.h>
#include <cerfcore/host/host_widget_registry.h>

#include <algorithm>

namespace cerffrontend {

REGISTER_SERVICE(StatusBar);

namespace {

constexpr Rgb     kBg{32, 32, 32};
constexpr Rgb     kSep{60, 60, 60};
constexpr Rgb     kBgLight{240, 240, 240};
constexpr Rgb     kSepLight{200, 200, 200};
constexpr Rgb     kRx{229, 80, 80};
constexpr Rgb     kTx{78, 201, 90};
constexpr Rgb     kDotRim{20, 20, 20};
constexpr Rgb     kRowText{220, 220, 220};
constexpr Rgb     kRowTextLight{40, 40, 40};
constexpr Rgb     kLatch{63, 185, 80};
constexpr Rgb     kHover{52, 52, 52};
constexpr Rgb     kHoverLight{218, 218, 218};
constexpr int     kGlowTicks     = 3;
constexpr int     kDotR          = 3;
constexpr uint8_t kDisabledAlpha = 150;
constexpr int     kRowPad        = 8;
constexpr int     kRowGap        = 6;
constexpr int     kRowSepInset   = 4;
constexpr int     kLatchHeight   = 2;

}

bool StatusBar::SampleActivity(cerfcore::HostWidget* w) {
    Glow& g = glow_[w];
    if (w->TakeRx())   g.rx = kGlowTicks;
    else if (g.rx > 0) --g.rx;
    if (w->TakeTx())   g.tx = kGlowTicks;
    else if (g.tx > 0) --g.tx;

    const bool now     = g.rx > 0 || g.tx > 0;
    const bool repaint = now || g.was_active;
    g.was_active       = now;
    return repaint;
}

std::vector<cerfcore::HostWidget*> StatusBar::ShownWidgets() const {
    std::vector<cerfcore::HostWidget*> shown = emu_.Get<cerfcore::HostWidgetRegistry>().Ordered();
    if (!filter_) return shown;
    const auto hidden = [this](const cerfcore::HostWidget* w) { return !filter_(w); };
    shown.erase(std::remove_if(shown.begin(), shown.end(), hidden), shown.end());
    return shown;
}

bool StatusBar::Relayout(int width, int height) {
    width_                                           = width;
    height_                                          = height;
    const std::vector<cerfcore::HostWidget*> ordered = ShownWidgets();
    const int widgets_w = static_cast<int>(ordered.size()) * kIconBoxW;
    const int row_w     = row_shown_ && row_width_ > 0 ? row_width_ + kRowGap : 0;
    scroll_             = std::clamp(scroll_, 0, std::max(0, row_w + widgets_w - width));

    const int          block_left = width + scroll_ - widgets_w;
    std::vector<Entry> next;
    next.reserve(ordered.size());
    for (size_t k = 0; k < ordered.size(); ++k) {
        const int left = block_left + static_cast<int>(k) * kIconBoxW;
        next.push_back({ordered[k], Rect{left, 0, left + kIconBoxW, height}});
    }

    bool changed = next.size() != layout_.size();
    for (size_t i = 0; !changed && i < next.size(); ++i)
        changed = next[i].widget != layout_[i].widget || !(next[i].box == layout_[i].box);
    layout_.swap(next);
    return changed;
}

bool StatusBar::Scroll(int delta) {
    const int before = scroll_;
    scroll_ += delta;
    Relayout(width_, height_);
    return scroll_ != before;
}

bool StatusBar::RefreshRow() {
    if (!row_shown_) return false;
    std::vector<RowButton> next    = emu_.Get<ButtonRow>().Buttons();
    const auto             same_as = [](const RowButton& a, const RowButton& b) {
        return a.kind == b.kind && a.vk == b.vk && a.group == b.group && a.item == b.item && a.label == b.label &&
               a.held == b.held && a.group_start == b.group_start;
    };
    if (next.size() == row_buttons_.size() &&
        std::equal(next.begin(), next.end(), row_buttons_.begin(), same_as))
        return false;
    row_buttons_ = std::move(next);
    return true;
}

int StatusBar::HoverTarget() const {
    if (!hovering_) return -1;
    const int row = RowIndexAt(hover_x_);
    if (row >= 0) return row;
    for (size_t i = 0; i < layout_.size(); ++i)
        if (hover_x_ >= layout_[i].box.left && hover_x_ < layout_[i].box.right)
            return static_cast<int>(row_.size() + i);
    return -1;
}

bool StatusBar::Hovered(const Rect& box) const {
    return hovering_ && hover_x_ >= box.left && hover_x_ < box.right;
}

bool StatusBar::SetHover(int x) {
    const int before = HoverTarget();
    hovering_        = true;
    hover_x_         = x;
    return HoverTarget() != before;
}

bool StatusBar::ClearHover() {
    const int before = HoverTarget();
    hovering_        = false;
    return before >= 0;
}

int StatusBar::RowIndexAt(int x) const {
    for (size_t i = 0; i < row_.size(); ++i)
        if (x >= row_[i].box.left && x < row_[i].box.right) return static_cast<int>(i);
    return -1;
}

StatusBar::TickResult StatusBar::Tick(int width, int height) {
    TickResult r;
    r.repaint |= RefreshRow();
    for (cerfcore::HostWidget* w : emu_.Get<cerfcore::HostWidgetRegistry>().Ordered())
        r.repaint |= SampleActivity(w);
    r.layout_changed = Relayout(width, height);
    r.repaint |= r.layout_changed;
    for (size_t i = 0; i < layout_.size(); ++i) {
        if (!layout_[i].widget->PollDirty()) continue;
        r.repaint = true;
        r.tooltips_changed.push_back(i);
    }
    return r;
}

void StatusBar::DrawComposited(Painter& p, cerfcore::HostWidget* w, const Rect& box, Rgb bar_bg) {
    emu_.Get<WidgetIconPainter>().Paint(p, box, w->Icon());
    if (!w->IsEnabled()) {
        p.BlendRect(box, bar_bg, kDisabledAlpha);
        return;
    }
    auto dot = [&](Rgb color, int cx, int cy) {
        p.Ellipse({cx - kDotR, cy - kDotR, cx + kDotR + 1, cy + kDotR + 1}, kDotRim, color);
    };
    const Glow& g = glow_[w];
    if (g.rx > 0) dot(kRx, box.left + kDotR + 1, box.bottom - kDotR - 2);
    if (g.tx > 0) dot(kTx, box.right - kDotR - 2, box.bottom - kDotR - 2);
}

void StatusBar::Paint(Painter& p, const Rect& client, bool dark) {
    const Rgb bar_bg = dark ? kBg : kBgLight;
    p.FillRect(client, bar_bg);
    const Point separator[] = {{client.left, client.top}, {client.right, client.top}};
    p.Polyline(separator, 2, dark ? kSep : kSepLight, 1);
    for (const Entry& e : layout_)
        if (Hovered(e.box)) p.FillRect(Rect{e.box.left, e.box.top + 1, e.box.right, e.box.bottom},
                                       dark ? kHover : kHoverLight);
    if (row_shown_) PaintRow(p, client, dark);
    PaintWidgets(p, bar_bg);
}

void StatusBar::PaintRow(Painter& p, const Rect& client, bool dark) {
    const Font       font{FontFace::kSystem, 0, false};
    std::vector<int> widths;
    widths.reserve(row_buttons_.size());
    int total = 0;
    for (const RowButton& b : row_buttons_) {
        widths.push_back(p.TextWidth(b.label, font) + 2 * kRowPad);
        total += widths.back();
    }
    if (total != row_width_) {
        row_width_ = total;
        Relayout(client.Width(), client.Height());
    }

    const Rgb text  = dark ? kRowText : kRowTextLight;
    const Rgb sep   = dark ? kSep : kSepLight;
    const int right = layout_.empty() ? client.right + scroll_ : layout_.front().box.left - kRowGap;
    int       left  = right - total;
    row_.clear();
    for (size_t i = 0; i < row_buttons_.size(); ++i) {
        const RowButton& b = row_buttons_[i];
        const Rect       box{left, client.top, left + widths[i], client.bottom};
        row_.push_back({b, box});
        if (Hovered(box)) p.FillRect(Rect{box.left, box.top + 1, box.right, box.bottom}, dark ? kHover : kHoverLight);
        if (b.group_start) {
            const Point line[] = {{box.left, box.top + kRowSepInset}, {box.left, box.bottom - kRowSepInset}};
            p.Polyline(line, 2, sep, 1);
        }
        p.DrawTextBox(box, b.label, font, text, text::kCenter | text::kVCenter | text::kSingleLine);
        if (b.held)
            p.FillRect(Rect{box.left + kRowPad, box.bottom - kLatchHeight - 1, box.right - kRowPad, box.bottom - 1},
                       kLatch);
        left += widths[i];
    }
    if (total > 0 && !layout_.empty()) {
        const int   x      = right + kRowGap / 2;
        const Point line[] = {{x, client.top + kRowSepInset}, {x, client.bottom - kRowSepInset}};
        p.Polyline(line, 2, sep, 1);
    }
}

void StatusBar::PaintWidgets(Painter& p, Rgb backdrop) {
    for (const Entry& e : layout_) DrawComposited(p, e.widget, e.box, backdrop);
}

std::string StatusBar::TooltipAt(size_t index) const {
    return index < layout_.size() ? layout_[index].widget->Tooltip() : std::string();
}

cerfcore::HostWidget* StatusBar::WidgetAt(int x) const {
    for (const Entry& e : layout_)
        if (x >= e.box.left && x < e.box.right) return e.widget;
    return nullptr;
}

bool StatusBar::WidgetBox(const cerfcore::HostWidget* w, Rect& out) const {
    for (const Entry& e : layout_) {
        if (e.widget != w) continue;
        out = e.box;
        return true;
    }
    return false;
}

bool StatusBar::CaptureWidgetBox(Rect& out) const {
    for (const Entry& e : layout_)
        if (e.widget->Group() == cerfcore::WidgetGroup::InputCapture)
            return WidgetBox(e.widget, out);
    return false;
}

bool StatusBar::PrimaryClick(cerfcore::HostWidget* w) {
    return w->TryPrimaryAction();
}

bool StatusBar::ContextMenu(cerfcore::HostWidget* w, std::vector<MenuItem>& out) {
    out = emu_.Get<WidgetMenuBuilder>().Build(w->Controls());
    if (w->ControlsAreOneAction() && out.size() == 1 && out[0].enabled && out[0].on_click &&
        out[0].submenu.empty()) {
        out[0].on_click();
        return false;
    }
    return true;
}

}
