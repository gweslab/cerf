#pragma once

#include <QQuickImageProvider>

class SvgIconProvider : public QQuickImageProvider {
public:
    SvgIconProvider();
    QImage requestImage(const QString& id, QSize* size, const QSize& requested_size) override;
};
