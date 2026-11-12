#pragma once

#include <QObject>
#include <QtQml/qqmlregistration.h>

class QGuiApplication;
class QJSEngine;
class QQmlEngine;
struct SystemBarsLink;

class AndroidSystemBars : public QObject {
    Q_OBJECT
    QML_NAMED_ELEMENT(SystemBars)
    QML_SINGLETON

public:
    ~AndroidSystemBars() override;

    static void               Install(QGuiApplication& app);
    static AndroidSystemBars* create(QQmlEngine* qml, QJSEngine* js);

    Q_INVOKABLE void Hide();

signals:
    void shown();

private:
    explicit AndroidSystemBars(QObject* parent) : QObject(parent) {}

    void FollowFocusWindow();

    SystemBarsLink* link_ = nullptr;
};
