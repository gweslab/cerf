#pragma once

#include <cstdint>
#include <string>

/* Non-Service mixin (HostWidget shape): a Service-derived input base adds it
   without making emu_ ambiguous. Kind picks how HostCanvasInput transforms host
   mouse messages for the active source. */
enum class PointerKind { Absolute, Relative, Stylus };

class PointerSource {
public:
    virtual ~PointerSource() = default;

    virtual std::wstring   SourceName()       const = 0;
    virtual const char*    SourceLabelKey()   const { return nullptr; }
    /* cerf.rc ICON resource the pointer widget draws while this source is active. */
    virtual const wchar_t* IconResourceName() const = 0;
    virtual int            SourcePriority()   const = 0;
    virtual PointerKind    Kind()             const = 0;
    virtual bool           SourceReady()      const { return true; }
};
