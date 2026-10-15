#pragma once

#include "../core/service.h"
#include "host_widget.h"

#include <string>

/* Status-bar audio-activity indicator shared by every sound system: MarkTx on
   sound output (green dot), MarkRx on microphone capture (red dot). */
class AudioActivityWidget : public Service, public HostWidget {
public:
    using Service::Service;

    /* Idempotent: a sound backend declares it exists, registering the indicator
       with the status bar on the first call. */
    void NotePresent();

    std::wstring WidgetName() const override { return L"Audio"; }
    std::wstring MenuLabel() const override;
    WidgetGroup  Group() const override { return WidgetGroup::Indicator; }
    std::wstring Tooltip() const override;

    void DrawIcon(HDC dc, const RECT& box) const override;

private:
    bool registered_ = false;
};
