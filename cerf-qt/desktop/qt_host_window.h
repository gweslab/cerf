#pragma once

#include <cerfcore/core/instance_gate.h>

#include <QMainWindow>
#include <QSize>

class QtHostWindow : public QMainWindow {
public:
    explicit QtHostWindow(cerfcore::CerfEmulator& emu) : gate_(emu) {}

    void ResizeTo(const QSize& size);

protected:
    void closeEvent(QCloseEvent* event) override;
    void changeEvent(QEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;

private:
    cerfcore::InstanceGate gate_;
    QSize                  expected_;
};
