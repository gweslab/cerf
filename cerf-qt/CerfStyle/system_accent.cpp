#include "system_accent.h"

#include <QGuiApplication>
#include <QStyleHints>

SystemAccent::SystemAccent(QObject* parent) : QObject(parent), host_(NewHostAccent(this)) {
    connect(host_, &HostAccent::changed, this, &SystemAccent::Refresh);
    connect(QGuiApplication::styleHints(), &QStyleHints::colorSchemeChanged, this, &SystemAccent::Refresh);
    Refresh();
}

QColor SystemAccent::Color() const { return shade_.fill; }

QColor SystemAccent::TextColor() const { return shade_.text; }

bool SystemAccent::Known() const { return shade_.fill.isValid(); }

QColor SystemAccent::DarkColor() const { return dark_fill_; }

bool SystemAccent::DarkKnown() const { return dark_fill_.isValid(); }

void SystemAccent::Refresh() {
    const AccentShade shade     = host_->Shade(QGuiApplication::styleHints()->colorScheme() == Qt::ColorScheme::Dark);
    const QColor      dark_fill = host_->Shade(true).fill;
    if (shade.fill == shade_.fill && shade.text == shade_.text && dark_fill == dark_fill_) return;
    shade_     = shade;
    dark_fill_ = dark_fill;
    emit changed();
}
