#pragma once

#include "../core/service.h"
#include "pointer_source.h"

#include <cstdint>

/* Relative pointing device (laptop touchpad / captured mouse), fed by the
   host mouse-lock path while HostInputCapture is captured. */

constexpr uint32_t kRelMouseLeft  = 0x1u;
constexpr uint32_t kRelMouseRight = 0x2u;

class RelativeMouseInput : public Service, public PointerSource {
public:
    using Service::Service;
    ~RelativeMouseInput() override = default;

    /* dx > 0 right, dy > 0 down (screen convention); button_mask is the
       current button state. Called on motion or a button transition. */
    virtual void OnRelativeMove(int dx, int dy, uint32_t button_mask) = 0;

    /* PointerSource - concretes override SourceName per controller. */
    std::wstring   SourceName()       const override { return L"Stock mouse"; }
    const char*    SourceLabelKey()   const override { return "input.stock_mouse"; }
    const wchar_t* IconResourceName() const override { return L"ICON_INPUT_PS2_MOUSE"; }
    int            SourcePriority()   const override { return 0; }
    PointerKind    Kind()             const override { return PointerKind::Relative; }
};
