#pragma once

#include <QQuickImageProvider>

class SvgFileImageProvider : public QQuickImageProvider {
public:
    SvgFileImageProvider();
    QImage requestImage(const QString& id, QSize* size, const QSize& requested_size) override;
};
