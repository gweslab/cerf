#pragma once

#include <QMargins>
#include <QMetaObject>
#include <QObject>
#include <QPointer>
#include <QQuickItem>
#include <QWindow>
#include <QtQml/qqmlregistration.h>

class WindowInsets : public QObject {
    Q_OBJECT
    QML_ELEMENT
    QML_UNCREATABLE("WindowInsets is an attached property")
    QML_ATTACHED(WindowInsets)
    Q_PROPERTY(qreal left READ Left NOTIFY changed FINAL)
    Q_PROPERTY(qreal top READ Top NOTIFY changed FINAL)
    Q_PROPERTY(qreal right READ Right NOTIFY changed FINAL)
    Q_PROPERTY(qreal bottom READ Bottom NOTIFY changed FINAL)
    Q_PROPERTY(qreal gap READ Gap WRITE SetGap NOTIFY changed FINAL)
    Q_PROPERTY(qreal leftMargin READ LeftMargin NOTIFY changed FINAL)
    Q_PROPERTY(qreal topMargin READ TopMargin NOTIFY changed FINAL)
    Q_PROPERTY(qreal rightMargin READ RightMargin NOTIFY changed FINAL)
    Q_PROPERTY(qreal bottomMargin READ BottomMargin NOTIFY changed FINAL)

public:
    explicit WindowInsets(QObject* attachee);

    static WindowInsets* qmlAttachedProperties(QObject* attachee);

    qreal Left() const { return margins_.left(); }
    qreal Top() const { return margins_.top(); }
    qreal Right() const { return margins_.right(); }
    qreal Bottom() const { return margins_.bottom(); }
    qreal Gap() const { return gap_; }
    void  SetGap(qreal gap);
    qreal LeftMargin() const;
    qreal TopMargin() const;
    qreal RightMargin() const;
    qreal BottomMargin() const;

Q_SIGNALS:
    void changed();

private Q_SLOTS:
    void FollowItem();

private:
    void  FollowWindow();
    void  Read();
    qreal WithGap(qreal inset) const;

    QObject*                attachee_;
    QPointer<QQuickItem>    item_;
    QPointer<QWindow>       window_;
    QMetaObject::Connection item_window_;
    QMetaObject::Connection window_margins_;
    QMetaObject::Connection window_height_;
    QMargins                margins_;
    qreal                   gap_ = 0;
};
