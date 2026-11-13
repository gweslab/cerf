#include "frame_scene_node.h"

#include "fresh_sampler_texture.h"
#include "present_effects.h"
#include "shader_chain_node.h"

#include <QMatrix4x4>
#include <QQuickWindow>
#include <QSGClipNode>
#include <QSGImageNode>
#include <QSGRectangleNode>
#include <QSGTransformNode>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <string>
#include <utility>

FrameSceneNode::FrameSceneNode(QQuickWindow* window) : window_(window) {
    fill_ = window->createRectangleNode();
    appendChildNode(fill_);
    clip_ = new QSGClipNode;
    clip_->setIsRectangular(true);
    appendChildNode(clip_);
    background_ = window->createRectangleNode();
    clip_->appendChildNode(background_);
    alt_slot_ = new QSGNode;
    clip_->appendChildNode(alt_slot_);
    turn_ = new QSGTransformNode;
    clip_->appendChildNode(turn_);
    shader_slot_ = new QSGNode;
    turn_->appendChildNode(shader_slot_);
    glow_slot_ = new QSGNode;
    turn_->appendChildNode(glow_slot_);
    frame_slot_ = new QSGNode;
    turn_->appendChildNode(frame_slot_);
    overlay_slot_ = new QSGNode;
    clip_->appendChildNode(overlay_slot_);
}

void FrameSceneNode::Update(const FrameLayers& layers, const QSizeF& item_size, const QColor& fill, QPointF scale) {
    fill_->setRect(QRectF(QPointF(0, 0), item_size));
    fill_->setColor(fill);
    const QRectF canvas(0, 0, layers.canvas_w / scale.x(), layers.canvas_h / scale.y());
    clip_->setClipRect(canvas);
    background_->setRect(canvas);
    background_->setColor(layers.background);
    ShowImage(alt_slot_, layers.alt, canvas, QSGTexture::Nearest, true);

    QMatrix4x4 matrix;
    matrix.scale(1.0 / scale.x(), 1.0 / scale.y());
    matrix *= QMatrix4x4(layers.turn);
    turn_->setMatrix(matrix);
    if (layers.glow == nullptr) {
        ClearSlot(glow_slot_);
    } else {
        const bool    fresh = glow_slot_->firstChild() == nullptr || layers.glow_generation != glow_generation_;
        QSGImageNode* glow  = SlotImage(glow_slot_, QSGTexture::Linear, true);
        if (fresh)
            glow->setTexture(CreateFreshSamplerTexture(window_, *layers.glow, QQuickWindow::TextureIsOpaque));
        glow->setRect(layers.glow_rect);
        glow_generation_ = layers.glow_generation;
    }
    if (!ShowShaded(layers)) {
        if (layers.capture && layers.capture->Pending()) layers.capture->Finish(ShaderCapture::State::kUnshaded, {});
        SetFrameKind(FrameKind::kImage);
        ShowImage(frame_slot_, layers.dimmed != nullptr ? layers.dimmed : layers.guest,
                  QRectF(0, 0, layers.target_w, layers.target_h), QSGTexture::Nearest, true);
    }
    ShowImage(overlay_slot_, layers.overlay, canvas, QSGTexture::Nearest, false);
}

bool FrameSceneNode::ShowShaded(const FrameLayers& layers) {
    if (!ShaderReady(layers)) return false;
    if (layers.guest == nullptr) {
        shader_->Suspend();
        return false;
    }
    const QSize target(layers.target_w, layers.target_h);
    QSize       size    = target;
    const int   largest = std::max(target.width(), target.height());
    const int   limit   = shader_->Runtime().MaxTextureSize();
    if (largest > limit)
        size = QSize(std::max(1, static_cast<int>(std::lround(static_cast<double>(target.width()) * limit / largest))),
                     std::max(1, static_cast<int>(std::lround(static_cast<double>(target.height()) * limit / largest))));
    std::string error;
    window_->beginExternalCommands();
    QSGTexture* output = shader_->Runtime().Output(size, error);
    window_->endExternalCommands();
    if (output == nullptr) {
        FailShader(layers, std::move(error));
        return false;
    }
    if (layers.dimmed != nullptr) return ShowFrozen(layers, target, size);
    frozen_valid_ = false;
    shader_->SetFrame(*layers.guest);
    if (layers.capture && layers.capture->Pending()) shader_->RequestCapture(layers.capture);
    SetFrameKind(FrameKind::kShaded);
    QSGImageNode* node = SlotImage(frame_slot_, size == target ? QSGTexture::Nearest : QSGTexture::Linear, false);
    node->setTexture(output);
    node->setRect(QRectF(0, 0, target.width(), target.height()));
    return true;
}

bool FrameSceneNode::ShowFrozen(const FrameLayers& layers, QSize target, QSize size) {
    const bool fresh = !frozen_valid_ || frozen_size_ != size || frozen_parameters_ != shader_parameters_;
    if (fresh) {
        std::string error;
        window_->beginExternalCommands();
        const bool frozen = shader_->Freeze(*layers.guest, frozen_, error);
        window_->endExternalCommands();
        if (!frozen) {
            FailShader(layers, std::move(error));
            return false;
        }
        frozen_image_ = QImage(static_cast<int>(frozen_.width), static_cast<int>(frozen_.height), QImage::Format_RGB32);
        std::memcpy(frozen_image_.bits(), frozen_.pixels.data(), frozen_.pixels.size() * sizeof(uint32_t));
        cerffrontend::PresentEffects::DesaturateAndDim(reinterpret_cast<uint32_t*>(frozen_image_.bits()),
                                                       static_cast<int>(frozen_.pixels.size()));
        frozen_valid_      = true;
        frozen_size_       = size;
        frozen_parameters_ = shader_parameters_;
    }
    if (layers.capture && layers.capture->Pending()) layers.capture->Finish(ShaderCapture::State::kCaptured, frozen_);
    const bool upload = fresh || frame_kind_ != FrameKind::kFrozen;
    SetFrameKind(FrameKind::kFrozen);
    QSGImageNode* node = SlotImage(frame_slot_, size == target ? QSGTexture::Nearest : QSGTexture::Linear, true);
    if (upload) node->setTexture(CreateFreshSamplerTexture(window_, frozen_image_, QQuickWindow::TextureIsOpaque));
    node->setRect(QRectF(0, 0, target.width(), target.height()));
    return true;
}

void FrameSceneNode::SetFrameKind(FrameKind kind) {
    if (frame_kind_ != kind) ClearSlot(frame_slot_);
    frame_kind_ = kind;
}

bool FrameSceneNode::ShaderReady(const FrameLayers& layers) {
    const ShaderChainSpec* spec = layers.shaders;
    if (spec == nullptr) {
        DropShader();
        shader_ready_      = false;
        shader_generation_ = 0;
        return false;
    }
    if (spec->generation != shader_generation_) {
        shader_generation_ = spec->generation;
        shader_parameters_ = spec->parameter_generation;
        if (spec->presets.empty()) {
            DropShader();
            *layers.shader_result = ShaderChainResult{spec->generation, true, {}};
            shader_ready_         = false;
        } else {
            shader_ready_ = BuildShader(*spec, *layers.shader_result);
        }
    }
    if (shader_ready_ && spec->parameter_generation != shader_parameters_) {
        shader_parameters_ = spec->parameter_generation;
        std::string error;
        if (!shader_->Runtime().ApplyParameters(spec->parameters, error)) FailShader(layers, std::move(error));
    }
    if (shader_ready_ && !shader_->RenderError().empty()) FailShader(layers, shader_->RenderError());
    return shader_ready_;
}

void FrameSceneNode::FailShader(const FrameLayers& layers, std::string error) {
    *layers.shader_result = ShaderChainResult{shader_generation_, false, std::move(error)};
    shader_ready_         = false;
    DropShader();
}

bool FrameSceneNode::BuildShader(const ShaderChainSpec& spec, ShaderChainResult& result) {
    result        = ShaderChainResult{spec.generation, false, {}};
    frozen_valid_ = false;
    if (shader_ == nullptr) {
        std::unique_ptr<ShaderRuntime> runtime = ShaderRuntime::Create(window_, result.error);
        if (!runtime) return false;
        shader_ = new ShaderChainNode(window_, std::move(runtime));
        shader_slot_->appendChildNode(shader_);
    }
    window_->beginExternalCommands();
    const bool built = shader_->Runtime().Build(spec, result.error);
    window_->endExternalCommands();
    if (!built) {
        DropShader();
        return false;
    }
    result.applied = true;
    return true;
}

void FrameSceneNode::DropShader() {
    frozen_valid_ = false;
    if (shader_ == nullptr) return;
    ClearSlot(shader_slot_);
    shader_ = nullptr;
}

void FrameSceneNode::ShowImage(QSGNode* slot, const QImage* image, const QRectF& rect,
                               QSGTexture::Filtering filtering, bool opaque) {
    if (image == nullptr) {
        ClearSlot(slot);
        return;
    }
    QSGImageNode* node = SlotImage(slot, filtering, true);
    node->setTexture(CreateFreshSamplerTexture(
        window_, *image, opaque ? QQuickWindow::TextureIsOpaque : QQuickWindow::CreateTextureOptions()));
    node->setRect(rect);
}

QSGImageNode* FrameSceneNode::SlotImage(QSGNode* slot, QSGTexture::Filtering filtering, bool owns_texture) {
    auto* node = static_cast<QSGImageNode*>(slot->firstChild());
    if (node == nullptr) {
        node = window_->createImageNode();
        node->setOwnsTexture(owns_texture);
        slot->appendChildNode(node);
    }
    node->setFiltering(filtering);
    return node;
}

void FrameSceneNode::ClearSlot(QSGNode* slot) {
    while (QSGNode* child = slot->firstChild()) {
        slot->removeChildNode(child);
        delete child;
    }
}
