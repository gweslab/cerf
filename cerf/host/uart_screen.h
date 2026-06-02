#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

class UartScreen : public Service {
public:
    using Service::Service;
    ~UartScreen() override;

    /* Push one completed debug-console line. Trailing newline
       characters are stripped by the caller. Lines beyond
       kMaxLines drop the oldest. */
    void AddLine(std::string_view line);

    /* True once at least one line has been added. State-transition
       trigger for HostWindow's splash → boot-log rendering. */
    bool HasOutput() const;

    /* Render into the host DIB. dc is HostWindow's memory DC
       wrapping the same pixels; used for GDI text + icon drawing.
       dib_bgra32 / width / height describe the same surface in
       raw-pixel form. Fills every byte of the buffer. */
    void RenderInto(HDC dc,
                    uint32_t* dib_bgra32,
                    uint32_t  width,
                    uint32_t  height);

private:
    static constexpr size_t kMaxLines = 500;

    mutable std::mutex      mtx_;
    std::deque<std::string> lines_;
    bool                    has_output_ = false;

    /* Two cached fonts, indexed by [small/regular] resolution tier.
       Created lazily on first RenderInto call that needs them
       (HDC is needed for CreateFontW's matching). */
    HFONT font_cache_[2] = { nullptr, nullptr };

    void DrawBootBar(uint32_t* dib_bgra32,
                     uint32_t  width,
                     uint32_t  height) const;
};
