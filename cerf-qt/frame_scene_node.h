#pragma once

#include "frame_layers.h"

#include <QColor>
#include <QImage>
#include <QPointF>
#include <QSGNode>
#include <QSGTexture>
#include <QSize>
#include <QSizeF>

#include <cstdint>
#include <string>

class QQuickWindow;
class QSGClipNode;
class QSGImageNode;
class QSGRectangleNode;
class QSGTransformNode;
class ShaderChainNode;

class FrameSceneNode : public QSGNode {
public:
    explicit FrameSceneNode(QQuickWindow* window);

    void Update(const FrameLayers& layers, const QSizeF& item_size, const QColor& fill, QPointF scale);

private:
    enum class FrameKind : uint8_t { kImage, kShaded, kFrozen };

    bool          ShowShaded(const FrameLayers& layers);
    bool          ShowFrozen(const FrameLayers& layers, QSize target, QSize size);
    void          SetFrameKind(FrameKind kind);
    bool          ShaderReady(const FrameLayers& layers);
    bool          BuildShader(const ShaderChainSpec& spec, ShaderChainResult& result);
    void          FailShader(const FrameLayers& layers, std::string error);
    void          DropShader();
    void          ShowImage(QSGNode* slot, const QImage* image, const QRectF& rect, QSGTexture::Filtering filtering,
                            bool opaque);
    QSGImageNode* SlotImage(QSGNode* slot, QSGTexture::Filtering filtering, bool owns_texture);
    static void   ClearSlot(QSGNode* slot);

    QQuickWindow*     window_;
    QSGRectangleNode* fill_       = nullptr;
    QSGClipNode*      clip_       = nullptr;
    QSGRectangleNode* background_ = nullptr;
    QSGNode*          alt_slot_   = nullptr;
    QSGTransformNode* turn_       = nullptr;
    QSGNode*          shader_slot_ = nullptr;
    QSGNode*          glow_slot_  = nullptr;
    QSGNode*          frame_slot_ = nullptr;
    QSGNode*          overlay_slot_ = nullptr;
    ShaderChainNode*  shader_      = nullptr;
    uint64_t          glow_generation_   = 0;
    uint64_t          shader_generation_ = 0;
    uint64_t          shader_parameters_ = 0;
    bool              shader_ready_      = false;
    FrameKind         frame_kind_        = FrameKind::kImage;
    ShadedFrame       frozen_;
    QImage            frozen_image_;
    QSize             frozen_size_;
    uint64_t          frozen_parameters_ = 0;
    bool              frozen_valid_      = false;
};
