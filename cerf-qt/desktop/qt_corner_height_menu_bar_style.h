#pragma once

#include <QProxyStyle>

class QtCornerHeightMenuBarStyle : public QProxyStyle {
public:
    using QProxyStyle::QProxyStyle;

    QSize sizeFromContents(ContentsType type, const QStyleOption* option, const QSize& size,
                           const QWidget* widget) const override;
};
