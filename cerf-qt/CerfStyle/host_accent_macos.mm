#include "host_accent.h"

#import <AppKit/AppKit.h>

namespace {

QColor ColorIn(NSColor* color, NSAppearanceName name) {
    __block QColor resolved;
    [[NSAppearance appearanceNamed:name] performAsCurrentDrawingAppearance:^{
        NSColor* rgb = [color colorUsingColorSpace:[NSColorSpace sRGBColorSpace]];
        if (rgb != nil)
            resolved = QColor::fromRgbF(static_cast<float>(rgb.redComponent), static_cast<float>(rgb.greenComponent),
                                        static_cast<float>(rgb.blueComponent), static_cast<float>(rgb.alphaComponent));
    }];
    return resolved;
}

AccentShade ShadeIn(NSAppearanceName name) {
    return AccentShade{ColorIn([NSColor controlAccentColor], name),
                       ColorIn([NSColor alternateSelectedControlTextColor], name)};
}

class ControlAccent : public HostAccent {
public:
    explicit ControlAccent(QObject* parent) : HostAccent(parent) {
        observer_ = [[NSNotificationCenter defaultCenter] addObserverForName:NSSystemColorsDidChangeNotification
                                                                      object:nil
                                                                       queue:[NSOperationQueue mainQueue]
                                                                  usingBlock:^(NSNotification*) {
                                                                      Reload();
                                                                  }];
        Reload();
    }

    ~ControlAccent() override { [[NSNotificationCenter defaultCenter] removeObserver:observer_]; }

protected:
    void Reload() override { Publish(ShadeIn(NSAppearanceNameAqua), ShadeIn(NSAppearanceNameDarkAqua)); }

private:
    id observer_ = nil;
};

}

HostAccent* NewHostAccent(QObject* parent) { return new ControlAccent(parent); }
