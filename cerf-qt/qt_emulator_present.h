#pragma once

#include "qt_frame_presenter.h"

#include <QImage>
#include <QtGlobal>

#include <cstdint>

class QtEmulatorView;

class QtEmulatorPresent final : public QtPresentHooks {
public:
    explicit QtEmulatorPresent(QtEmulatorView& view) : view_(view) {}

    void OnPresentTick(cerfcore::CerfEmulator& emu, bool source_has_frame) override;
    bool RenderAlt(cerfcore::CerfEmulator& emu, uint32_t* bits, int w, int h, qreal dpr) override;
    bool ShouldDesaturate(cerfcore::CerfEmulator& emu) override;
    void RenderOverlay(cerfcore::CerfEmulator& emu, QImage& present, int w, int h, qreal dpr) override;

private:
    static int Dpi(qreal dpr);

    QtEmulatorView& view_;
};
