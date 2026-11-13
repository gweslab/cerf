#include "frame_view_item.h"

#include "frame_scene_node.h"

#include <QQuickWindow>

QSGNode* FrameViewItem::UpdateNode(QSGNode* old_node) {
    auto* node = static_cast<FrameSceneNode*>(old_node);
    if (node == nullptr) node = new FrameSceneNode(window());
    const FrameLayers* layers = PresentLayers();
    node->Update(layers != nullptr ? *layers : FrameLayers{}, size(), FillColor(), PixelScale());
    return node;
}
