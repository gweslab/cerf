#pragma once

#include <QObject>

class QCoreApplication;

class QtBackGesture : public QObject {
public:
    explicit QtBackGesture(QCoreApplication& app);

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;

private:
    bool Begin(QObject* window, QEvent* event);

    int  depth_      = 0;
    bool handled_    = false;
    bool delivering_ = false;
};
