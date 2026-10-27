#pragma once

#include <cerfcore/core/service.h>

class QWidget;

class QtFocusPolicy : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool MayActivate() const;

    void Show(QWidget* window) const;
    void Raise(QWidget* window) const;
    void Focus(QWidget* widget) const;
};
