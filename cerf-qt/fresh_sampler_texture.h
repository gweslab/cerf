#pragma once

#include <QImage>
#include <QQuickWindow>
#include <QSGTexture>

QSGTexture* FreshSampler(QSGTexture* texture);
QSGTexture* CreateFreshSamplerTexture(QQuickWindow* window, const QImage& image,
                                      QQuickWindow::CreateTextureOptions options);
