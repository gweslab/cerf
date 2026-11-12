#pragma once

#include "qt_window_fit.h"

#include <QSize>
#include <Qt>

#include <cstdint>
#include <optional>

class QQuickWindow;

class ContentWindowState {
public:
    bool                     IsFullscreen() const { return fullscreen_; }
    std::optional<WindowFit> PlanFit(const QQuickWindow& window, uint32_t content_w, uint32_t content_h) const;
    void                     ApplyFit(QQuickWindow& window, const WindowFit& fit) const;
    Qt::WindowStates         ToggledStates() const;
    std::optional<QSize>     RestoredSize() const;
    void                     ToggleFullscreen(QQuickWindow& window);

private:
    bool  fullscreen_    = false;
    bool  was_maximized_ = false;
    QSize normal_size_;
};
