#pragma once

#include <cerfcore/core/service.h>

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

    QString       UiFamily() const { return ui_family_; }
    QString       MonoFamily() const { return mono_family_; }
    const QImage& SvgImage(std::string_view stem, int width, int height, qreal dpr);

private:
    QString LoadFamily(const char* file_name);

    QString                                                    ui_family_;
    QString                                                    mono_family_;
    std::map<std::tuple<std::string, int, int, qreal>, QImage> svgs_;
};
