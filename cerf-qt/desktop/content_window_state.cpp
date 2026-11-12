#include "content_window_state.h"

#include <QQuickWindow>

namespace {

constexpr char kChromeShown[] = "chromeShown";

}

std::optional<WindowFit> ContentWindowState::PlanFit(const QQuickWindow& window, uint32_t content_w,
                                                     uint32_t content_h) const {
    if (content_w == 0 || content_h == 0 || fullscreen_) return std::nullopt;
    return FitAroundContent(window, content_w, content_h);
}

void ContentWindowState::ApplyFit(QQuickWindow& window, const WindowFit& fit) const {
    if (window.windowStates().testFlag(Qt::WindowMaximized)) window.showNormal();
    window.resize(fit.client);
    window.setFramePosition(fit.position);
}

Qt::WindowStates ContentWindowState::ToggledStates() const {
    if (!fullscreen_) return Qt::WindowFullScreen;
    return was_maximized_ ? Qt::WindowMaximized : Qt::WindowNoState;
}

std::optional<QSize> ContentWindowState::RestoredSize() const {
    if (!fullscreen_ || was_maximized_) return std::nullopt;
    return normal_size_;
}

void ContentWindowState::ToggleFullscreen(QQuickWindow& window) {
    if (!fullscreen_) {
        was_maximized_ = window.windowStates().testFlag(Qt::WindowMaximized);
        normal_size_   = window.geometry().size();
        fullscreen_    = true;
        window.setProperty(kChromeShown, false);
        window.showFullScreen();
        return;
    }
    fullscreen_ = false;
    window.setProperty(kChromeShown, true);
    if (was_maximized_) window.showMaximized();
    else                window.showNormal();
}
