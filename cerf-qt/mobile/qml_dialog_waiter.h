#pragma once

#include <QEventLoop>
#include <QObject>
#include <QString>
#include <QVariant>

class QmlDialogWaiter : public QObject {
    Q_OBJECT

public:
    void            Watch(QObject* dialog);
    void            Wait();
    const QVariant& Result() const { return result_; }

public slots:
    void TakeChoice(const QString& text);
    void TakeResult(const QVariant& result);
    void TakeCancel();

private:
    void Finish(QVariant result);

    QEventLoop loop_;
    QVariant   result_;
    bool       done_ = false;
};
