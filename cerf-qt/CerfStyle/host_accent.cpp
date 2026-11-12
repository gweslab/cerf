#include "host_accent.h"

QColor HostAccent::Fill(bool dark) const { return dark ? dark_ : light_; }

void HostAccent::Publish(const QColor& light, const QColor& dark) {
    light_ = light;
    dark_  = dark;
    emit changed();
}
