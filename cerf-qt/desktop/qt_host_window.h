#pragma once

#include <QMainWindow>
#include <QSize>

class QtMainWindow;

class QtHostWindow : public QMainWindow {
public:
    explicit QtHostWindow(QtMainWindow& owner) : owner_(owner) {}

    void ResizeTo(const QSize& size);

protected:
    void closeEvent(QCloseEvent* event) override;
    void changeEvent(QEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;

private:
    QtMainWindow& owner_;
    QSize         expected_;
};
