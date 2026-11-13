#pragma once

#include "fill_color_item.h"

#include <QImage>
#include <QtQml/qqmlregistration.h>

class QPainter;

class DevicePixelItem : public FillColorItem {
    Q_OBJECT
    QML_ANONYMOUS

public:
    using FillColorItem::FillColorItem;

    virtual void Paint(QPainter* painter) = 0;

    void SetOpaquePainting(bool opaque) { opaque_ = opaque; }

protected:
    QSGNode* UpdateNode(QSGNode* old_node) override;

private:
    QImage image_;
    bool   opaque_ = false;
};
