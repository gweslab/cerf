#include "qml_dialog_waiter.h"

#include "../nested_event_loops.h"
#include "../qt_qml_value.h"

#include <QMetaObject>

void QmlDialogWaiter::Watch(QObject* dialog) {
    const QMetaObject* meta = dialog->metaObject();
    if (meta->indexOfSignal("choice(QString)") >= 0) {
        QObject::connect(dialog, SIGNAL(choice(QString)), this, SLOT(TakeChoice(QString)));
    } else if (meta->indexOfSignal("finished(QVariant)") >= 0) {
        QObject::connect(dialog, SIGNAL(finished(QVariant)), this, SLOT(TakeResult(QVariant)));
    } else {
        QObject::connect(dialog, SIGNAL(done(QVariant)), this, SLOT(TakeResult(QVariant)));
        QObject::connect(dialog, SIGNAL(closed()), this, SLOT(TakeCancel()));
    }
}

void QmlDialogWaiter::TakeCancel() { Finish(QVariant()); }

void QmlDialogWaiter::Wait(NestedEventLoops& loops) {
    if (!done_) loops.Run(loop_);
}

void QmlDialogWaiter::TakeChoice(const QString& text) { Finish(text); }

void QmlDialogWaiter::TakeResult(const QVariant& result) { Finish(PlainQmlValue(result)); }

void QmlDialogWaiter::Finish(QVariant result) {
    if (done_) return;
    done_   = true;
    result_ = std::move(result);
    loop_.quit();
}
