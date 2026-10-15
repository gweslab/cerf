#pragma once

#include "../core/service.h"
#include "pointer_source.h"

class TouchInput : public Service, public PointerSource {
public:
    using Service::Service;
    ~TouchInput() override = default;

    virtual void OnPenDown    (int x, int y) = 0;
    virtual void OnPenMove    (int x, int y) = 0;
    virtual void OnPenUp      (int x, int y) = 0;
    virtual void OnCaptureLost()             = 0;

    /* PointerSource - the stock resistive/stylus panel. */
    std::wstring   SourceName()       const override { return L"Stock stylus"; }
    const char*    SourceLabelKey()   const override { return "input.stock_stylus"; }
    const wchar_t* IconResourceName() const override { return L"ICON_INPUT_STYLUS"; }
    int            SourcePriority()   const override { return 0; }
    PointerKind    Kind()             const override { return PointerKind::Stylus; }
};
