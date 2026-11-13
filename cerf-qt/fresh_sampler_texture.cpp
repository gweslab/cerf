#include "fresh_sampler_texture.h"

QSGTexture* FreshSampler(QSGTexture* texture) {
    const QSGTexture::Filtering filtering = texture->filtering();
    texture->setFiltering(filtering == QSGTexture::Nearest ? QSGTexture::Linear : QSGTexture::Nearest);
    texture->setFiltering(filtering);
    return texture;
}

QSGTexture* CreateFreshSamplerTexture(QQuickWindow* window, const QImage& image,
                                      QQuickWindow::CreateTextureOptions options) {
    return FreshSampler(window->createTextureFromImage(image, options));
}
