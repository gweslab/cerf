#pragma once

#include <QObject>

class QQuickItem;

class SoftKeyboardRequest : public QObject {
    Q_OBJECT

public:
    explicit SoftKeyboardRequest(QQuickItem& input_item);

    bool Requested() const { return requested_; }
    bool Offered() const { return offered_; }
    void Toggle();
    void SetOffered(bool offered);

signals:
    void requestedChanged();
    void offeredChanged();

private:
    void OnKeyboardVisibleChanged();
    void Set(bool requested);

    QQuickItem& input_item_;
    bool        requested_ = false;
    bool        offered_   = false;
};
