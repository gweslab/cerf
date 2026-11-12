#pragma once

#include <cerfcore/core/service.h>

class QQuickItem;
class QWindow;

class QtFocusPolicy : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool MayActivate() const;
    void Show(QWindow& window) const;
    void Raise(QWindow& window) const;
    void Focus(QQuickItem& item) const;
};
