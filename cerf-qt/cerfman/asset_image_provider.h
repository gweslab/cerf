#pragma once

#include <QQuickImageProvider>

class AssetImageProvider : public QQuickImageProvider {
public:
    AssetImageProvider();
    QImage requestImage(const QString& id, QSize* size, const QSize& requested_size) override;
};
