#include <cerfcore/host/keyboard_mapping_view.h>

#include "../qt_painter.h"
#include "qt_main_window.h"
#include "qt_theme.h"

#include "keyboard_mapping_panel.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/keyboard_map.h>

#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QPointer>
#include <QWidget>

namespace {

using Panel = cerffrontend::KeyboardMappingPanel;

class KeyboardMappingWidget : public QWidget {
public:
    KeyboardMappingWidget(cerfcore::CerfEmulator& emu, QWidget* owner)
        : QWidget(owner, Qt::Tool), emu_(emu) {
        setWindowTitle(QString::fromUtf8(Panel::kTitle));
        setAttribute(Qt::WA_DeleteOnClose);
        setFixedSize(Panel::kClientW, Panel::kClientH);
        if (owner) {
            const QRect o = owner->frameGeometry();
            move(o.left() + (o.width() - width()) / 2, o.top() + (o.height() - height()) / 2);
        }
    }

protected:
    void paintEvent(QPaintEvent*) override {
        QPainter  p(this);
        QtPainter painter(emu_, p);
        emu_.Get<Panel>().Paint(painter, cerffrontend::Rect{0, 0, width(), height()},
                                emu_.Get<QtTheme>().IsDark());
    }

    void mouseReleaseEvent(QMouseEvent* event) override {
        if (event->button() != Qt::LeftButton) return;
        const QPoint pos = event->position().toPoint();
        if (emu_.Get<Panel>().OnClick(pos.x(), pos.y())) update();
    }

    void keyPressEvent(QKeyEvent* event) override {
        if (event->key() == Qt::Key_Escape) close();
    }

private:
    cerfcore::CerfEmulator& emu_;
};

class QtKeyboardMappingView : public cerfcore::KeyboardMappingView {
public:
    using cerfcore::KeyboardMappingView::KeyboardMappingView;

    bool ShouldRegister() override { return emu_.TryGet<cerfcore::KeyboardMap>() != nullptr; }

    void Show() override {
        if (window_) {
            window_->raise();
            window_->activateWindow();
            return;
        }
        emu_.Get<Panel>().Reset();
        window_ = new KeyboardMappingWidget(emu_, emu_.Get<QtMainWindow>().Window());
        window_->show();
        window_->raise();
        window_->activateWindow();
    }

private:
    QPointer<KeyboardMappingWidget> window_;
};

}

REGISTER_SERVICE_AS(QtKeyboardMappingView, cerfcore::KeyboardMappingView);
