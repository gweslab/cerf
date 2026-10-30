#pragma once

#include <cerfcore/core/instance_gate.h>

#include <QImage>
#include <QTimer>
#include <QWidget>

namespace cerfcore { class HostWidget; }

class QtStatusBar : public QWidget {
public:
    QtStatusBar(cerfcore::CerfEmulator& emu, QWidget* parent);

    bool WidgetScreenRect(cerfcore::CerfEmulator& emu, const cerfcore::HostWidget* w, QRect& out) const;
    bool CaptureWidgetScreenRect(cerfcore::CerfEmulator& emu, QRect& out) const;

protected:
    void paintEvent(QPaintEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void changeEvent(QEvent* event) override;
    void mousePressEvent(QMouseEvent* event) override;
    void mouseReleaseEvent(QMouseEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void leaveEvent(QEvent* event) override;
    void wheelEvent(QWheelEvent* event) override;
    bool event(QEvent* event) override;

private:
    void Tick();
    void SecondaryAction(cerfcore::CerfEmulator& emu, cerfcore::HostWidget* w, const QPoint& pos);
    int  EntryAt(cerfcore::CerfEmulator& emu, const QPoint& pos) const;

    cerfcore::InstanceGate gate_;
    QTimer                 tick_;
    QImage                 image_;
    int                    tip_entry_ = -1;
};
