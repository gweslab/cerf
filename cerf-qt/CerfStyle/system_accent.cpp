#include "system_accent.h"

#include <QGuiApplication>
#include <QStyleHints>

#include <cstdlib>

namespace {

constexpr int kRedWeight   = 299;
constexpr int kGreenWeight = 587;
constexpr int kBlueWeight  = 114;

int Brightness(const QColor& color) {
    return color.red() * kRedWeight + color.green() * kGreenWeight + color.blue() * kBlueWeight;
}

}

SystemAccent::SystemAccent(QObject* parent) : QObject(parent), host_(NewHostAccent(this)) {
    connect(host_, &HostAccent::changed, this, &SystemAccent::Refresh);
    connect(QGuiApplication::styleHints(), &QStyleHints::colorSchemeChanged, this, &SystemAccent::Refresh);
    Refresh();
}

QColor SystemAccent::Color() const { return fill_; }

bool SystemAccent::Known() const { return fill_.isValid(); }

QColor SystemAccent::DarkColor() const { return dark_fill_; }

bool SystemAccent::DarkKnown() const { return dark_fill_.isValid(); }

QColor SystemAccent::TextOn(const QColor& fill, const QColor& dark_text, const QColor& light_text) const {
    const int background = Brightness(fill);
    const int to_dark    = std::abs(background - Brightness(dark_text));
    const int to_light   = std::abs(background - Brightness(light_text));
    return to_dark >= to_light ? dark_text : light_text;
}

void SystemAccent::Refresh() {
    const QColor fill      = host_->Fill(QGuiApplication::styleHints()->colorScheme() == Qt::ColorScheme::Dark);
    const QColor dark_fill = host_->Fill(true);
    if (fill == fill_ && dark_fill == dark_fill_) return;
    fill_      = fill;
    dark_fill_ = dark_fill;
    emit changed();
}
