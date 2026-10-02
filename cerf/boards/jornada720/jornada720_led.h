#pragma once

#include "../../core/service.h"
#include "../../host/host_widget.h"

#include <mutex>

/* LED is behind the MCU (gwes.exe nled driver sub_927C4: 0xE1=on 0xE2=blink
   0xE3=off; sub_926CC: 0xE0 -> status bit0=on bit1=blink). The button is GPIO13
   falling edge (gwes sub_928F4 arms GFER bit13) -> SYSINTR 22 -> gwes posts
   0x464 to gweWinCENotify (acknowledge/snooze). */
class Jornada720Led : public Service, public HostWidget {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    enum class State { Off, On, Blink };

    /* MCU command handlers (SSP/JIT thread). */
    void    SetState(State s);
    uint8_t StatusByte() const;   /* 0xE0 reply: off=0x00 on=0x01 blink=0x03 */

    /* HostWidget */
    std::wstring WidgetName() const override { return L"Notification LED"; }
    WidgetGroup  Group() const override { return WidgetGroup::Indicator; }
    std::wstring Tooltip() const override;
    bool         TryPrimaryAction() override { PressButton(); return true; }
    std::vector<WidgetMenuItem> BuildMenu() override;
    void         DrawIcon(HDC dc, const RECT& box) const override;
    bool         PollDirty() override;

private:
    void  PressButton();
    State CurrentState() const;

    mutable std::mutex state_mutex_;
    State              state_ = State::Off;

    /* UI-thread repaint tracking (blink phase included). */
    State last_drawn_state_ = State::Off;
    bool  last_drawn_lit_   = false;
};
