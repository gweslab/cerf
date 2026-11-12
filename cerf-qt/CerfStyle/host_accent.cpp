#include "host_accent.h"

AccentShade HostAccent::Shade(bool dark) const { return dark ? dark_ : light_; }

void HostAccent::Publish(const AccentShade& light, const AccentShade& dark) {
    light_ = light;
    dark_  = dark;
    emit changed();
}
