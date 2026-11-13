#pragma once

#include "shader_capture.h"
#include "shader_chain_spec.h"

#include <QColor>
#include <QImage>
#include <QRectF>
#include <QTransform>

#include <cstdint>
#include <memory>

struct FrameLayers {
    QColor        background;
    int           canvas_w = 0;
    int           canvas_h = 0;
    const QImage* alt      = nullptr;
    const QImage* guest    = nullptr;
    const QImage* dimmed   = nullptr;
    QTransform    turn;
    int           target_w = 0;
    int           target_h = 0;
    const QImage* glow     = nullptr;
    QRectF        glow_rect;
    uint64_t      glow_generation = 0;
    const QImage* overlay  = nullptr;
    const ShaderChainSpec* shaders       = nullptr;
    ShaderChainResult*     shader_result = nullptr;
    std::shared_ptr<ShaderCapture> capture;
};
