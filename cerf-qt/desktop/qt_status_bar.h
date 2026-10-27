#pragma once

#include <cerfcore/core/cerf_emulator.h>

#include <QImage>
#include <QTimer>
#include <QWidget>

namespace cerfcore { class HostWidget; }

class QtStatusBar : public QWidget {
public:
    QtStatusBar(cerfcore::CerfEmulator& emu, QWidget* parent);

    bool WidgetScreenRect(const cerfcore::HostWidget* w, QRect& out) const;
    bool CaptureWidgetScreenRect(QRect& out) const;

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
    void RowHeld();
    void SecondaryAction(cerfcore::HostWidget* w, const QPoint& pos);
    int  EntryAt(const QPoint& pos) const;

    cerfcore::CerfEmulator& emu_;
    QTimer                  tick_;
    QTimer                  row_hold_;
    QImage                  image_;
    int                     tip_entry_   = -1;
    int                     row_pressed_ = -1;
};
