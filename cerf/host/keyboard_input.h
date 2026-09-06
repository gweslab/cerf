#pragma once

#include "../core/service.h"

#include <cstdint>
#include <string>

/* A keyboard source. Each concrete self-registers with KeyboardRouter from its
   OnReady (like peripherals/widgets); the router forwards host keys to the one
   active source and the keyboard widget switches between them. */
class KeyboardInput : public Service {
public:
    using Service::Service;
    ~KeyboardInput() override = default;

    virtual void OnHostKey(uint8_t vk, bool key_up) = 0;

    virtual bool CanDeliverVk(uint8_t vk) const;

    virtual std::wstring SourceName() const { return L"Stock keyboard"; }
    virtual int SourcePriority() const { return 0; }
    virtual bool SourceReady() const { return true; }
    /* cerf.rc ICON resource the keyboard widget draws while this source is active. */
    virtual const wchar_t* IconResourceName() const { return L"ICON_KEYBOARD"; }
};
