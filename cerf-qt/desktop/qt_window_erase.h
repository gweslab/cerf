#pragma once

#include <QAbstractNativeEventFilter>

class QCoreApplication;

class QtWindowErase : public QAbstractNativeEventFilter {
public:
    explicit QtWindowErase(QCoreApplication& app);

    QtWindowErase(const QtWindowErase&)            = delete;
    QtWindowErase& operator=(const QtWindowErase&) = delete;

    bool nativeEventFilter(const QByteArray& type, void* message, qintptr* result) override;
};
