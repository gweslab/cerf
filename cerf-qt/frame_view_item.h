#pragma once

#include "fill_color_item.h"
#include "frame_layers.h"

#include <QtQml/qqmlregistration.h>

class FrameViewItem : public FillColorItem {
    Q_OBJECT
    QML_ANONYMOUS

public:
    using FillColorItem::FillColorItem;

protected:
    virtual const FrameLayers* PresentLayers() = 0;

    QSGNode* UpdateNode(QSGNode* old_node) override;
};
