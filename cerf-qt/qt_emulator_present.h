#pragma once

#include "qt_frame_presenter.h"

#include <QImage>
#include <QtGlobal>

#include <cstdint>
#include <functional>

namespace cerfcore {
class CerfEmulator;
}

class QtEmulatorPresent final : public QtPresentHooks {
public:
    QtEmulatorPresent(cerfcore::CerfEmulator& emu, std::function<qreal()> dpr, std::function<void()> framebuffer_ready)
        : emu_(emu), dpr_(std::move(dpr)), framebuffer_ready_(std::move(framebuffer_ready)) {}

    void OnPresentTick(bool source_has_frame) override;
    bool RenderAlt(uint32_t* bits, int w, int h) override;
    bool ShouldDesaturate() override;
    void RenderOverlay(QImage& present, int w, int h) override;

private:
    int Dpi() const;

    cerfcore::CerfEmulator& emu_;
    std::function<qreal()>  dpr_;
    std::function<void()>   framebuffer_ready_;
};
