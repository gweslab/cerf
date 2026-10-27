#pragma once

#include "painter.h"

#include <cerfcore/core/service.h>

#include <QFont>
#include <QImage>
#include <QString>

#include <map>
#include <string>
#include <string_view>
#include <tuple>

class QtPaintResources : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override;

    QFont         Font(const cerffrontend::Font& font) const;
    const QImage& Icon(std::string_view stem, int px, qreal dpr);
    const QImage& SvgImage(std::string_view stem, int width, int height, qreal dpr);

private:
    QString LoadFamily(const char* file_name);

    QString                                                    ui_family_;
    QString                                                    mono_family_;
    std::map<std::tuple<std::string, int, int, qreal>, QImage> svgs_;
};
