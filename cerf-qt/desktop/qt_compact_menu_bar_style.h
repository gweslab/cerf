#pragma once

#include <QProxyStyle>

class QtCompactMenuBarStyle : public QProxyStyle {
public:
    using QProxyStyle::QProxyStyle;

    QSize sizeFromContents(ContentsType type, const QStyleOption* option, const QSize& size,
                           const QWidget* widget) const override;
    void  drawControl(ControlElement element, const QStyleOption* option, QPainter* painter,
                      const QWidget* widget) const override;
};
