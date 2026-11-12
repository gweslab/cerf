#include "global_menu_bar.h"

#include "../menu_source.h"
#include "../tinted_symbol_icon.h"
#include "../widget_menu_model.h"

#include <cerfcore/core/product_name.h>

#include <QColor>
#include <QCoreApplication>
#include <QGuiApplication>
#include <QImage>
#include <QMetaObject>
#include <QSize>
#include <QString>
#include <QVariantMap>
#include <QWindow>

#include <algorithm>
#include <cmath>
#include <vector>

#import <AppKit/AppKit.h>

@interface CerfGlobalMenuItem : NSMenuItem
@end

@implementation CerfGlobalMenuItem
@end

@interface CerfMenuPick : NSObject {
    GlobalMenuBar::Native* native_;
    int                    index_;
}
- (instancetype)initWithNative:(GlobalMenuBar::Native*)native index:(int)index;
- (void)pick:(id)sender;
@end

@interface CerfMenuFiller : NSObject <NSMenuDelegate> {
    GlobalMenuBar::Native* native_;
    int                    index_;
}
- (instancetype)initWithNative:(GlobalMenuBar::Native*)native index:(int)index;
@end

namespace {

constexpr int kRowIconPoints = 20;

NSString* ItemTitle(const QString& text) {
    const qsizetype tab = text.indexOf(QLatin1Char('\t'));
    if (tab < 0) return text.toNSString();
    return (text.left(tab) + QLatin1String(" (") + text.mid(tab + 1) + QLatin1Char(')')).toNSString();
}

CGFloat DensestBackingScale() {
    CGFloat scale = 1.0;
    for (NSScreen* screen in [NSScreen screens]) scale = std::max(scale, screen.backingScaleFactor);
    return scale;
}

NSImage* RowIcon(const QString& stem) {
    const int    side  = static_cast<int>(std::lround(kRowIconPoints * DensestBackingScale()));
    const QImage image = TintedSymbolIcon(stem, QSize(side, side), QColor(Qt::black));
    CGImageRef   cg    = image.toCGImage();
    auto*        rep   = [[[NSBitmapImageRep alloc] initWithCGImage:cg] autorelease];
    CGImageRelease(cg);
    rep.size      = NSMakeSize(kRowIconPoints, kRowIconPoints);
    NSImage* icon = [[[NSImage alloc] initWithSize:rep.size] autorelease];
    [icon addRepresentation:rep];
    [icon setTemplate:YES];
    return icon;
}

bool HoldsCerfMenus(NSMenu* main) {
    for (NSMenuItem* item in main.itemArray) {
        if ([item isKindOfClass:[CerfGlobalMenuItem class]]) return true;
    }
    return false;
}

bool Blocked() { return QGuiApplication::modalWindow() != nullptr; }

bool Enabled(NSInteger tag, bool blocked) { return tag >= 0 && !blocked; }

void Arm(id control, NSInteger tag, id pick, bool blocked) {
    [control setTag:tag];
    [control setTarget:pick];
    [control setAction:@selector(pick:)];
    [control setEnabled:Enabled(tag, blocked)];
}

void AddSeparator(NSMenu* menu) {
    if (menu.numberOfItems > 0 && ![menu itemAtIndex:menu.numberOfItems - 1].separatorItem)
        [menu addItem:[NSMenuItem separatorItem]];
}

void DropTrailingSeparator(NSMenu* menu) {
    if (menu.numberOfItems > 0 && [menu itemAtIndex:menu.numberOfItems - 1].separatorItem)
        [menu removeItemAtIndex:menu.numberOfItems - 1];
}

NSInteger FirstSeparator(NSMenu* menu) {
    for (NSInteger i = 0; i < menu.numberOfItems; ++i) {
        if ([menu itemAtIndex:i].separatorItem) return i;
    }
    return -1;
}

}

struct GlobalMenuBar::Native {
    Native(QWindow& owner, MenuSource& menus, QObject& owner_bar);
    ~Native();

    void        Install();
    void        Fill(int index, NSMenu* menu);
    void        Pick(int index, NSInteger tag);
    void        Append(NSMenu* menu, const QVariantList& entries, int index, bool blocked);
    NSMenuItem* RowItem(const QVariantList& buttons, int index, bool blocked);
    void        PlaceInAppMenu(const QVariantMap& entry, int index, bool blocked);
    void        RemoveAppItems(int index);

    QWindow&              window;
    MenuSource&           source;
    QObject&              bar;
    std::vector<QObject*> keys;
    NSMutableArray*       top_items = [[NSMutableArray alloc] init];
    NSMutableArray*       fillers   = [[NSMutableArray alloc] init];
    NSMutableArray*       picks     = [[NSMutableArray alloc] init];
    NSMutableArray*       app_items = [[NSMutableArray alloc] init];
};

@implementation CerfMenuPick
- (instancetype)initWithNative:(GlobalMenuBar::Native*)native index:(int)index {
    if ((self = [super init])) {
        native_ = native;
        index_  = index;
    }
    return self;
}

- (void)pick:(id)sender {
    native_->Pick(index_, [sender tag]);
}

- (BOOL)validateMenuItem:(NSMenuItem*)item {
    return Enabled(item.tag, Blocked());
}
@end

@implementation CerfMenuFiller
- (instancetype)initWithNative:(GlobalMenuBar::Native*)native index:(int)index {
    if ((self = [super init])) {
        native_ = native;
        index_  = index;
    }
    return self;
}

- (void)menuNeedsUpdate:(NSMenu*)menu {
    native_->Fill(index_, menu);
}
@end

GlobalMenuBar::Native::Native(QWindow& owner, MenuSource& menus, QObject& owner_bar)
    : window(owner), source(menus), bar(owner_bar) {
    const QStringList titles = source.MenuTitles();
    for (int index = 0; index < static_cast<int>(titles.size()); ++index) {
        NSString* title       = titles[index].toNSString();
        NSMenu*   menu        = [[[NSMenu alloc] initWithTitle:title] autorelease];
        auto*     filler      = [[[CerfMenuFiller alloc] initWithNative:this index:index] autorelease];
        menu.autoenablesItems = NO;
        menu.delegate         = filler;
        auto* item   = [[[CerfGlobalMenuItem alloc] initWithTitle:title action:nil keyEquivalent:@""] autorelease];
        item.submenu = menu;
        keys.push_back(new QObject(&bar));
        [top_items addObject:item];
        [fillers addObject:filler];
        [picks addObject:[[[CerfMenuPick alloc] initWithNative:this index:index] autorelease]];
        [app_items addObject:[NSMutableArray array]];
        Fill(index, menu);
    }
    QObject::connect(&window, &QWindow::activeChanged, &bar, [this] {
        if (window.isActive()) Install();
    });
    if (!HoldsCerfMenus(NSApp.mainMenu)) Install();
}

GlobalMenuBar::Native::~Native() {
    NSMenu* main = NSApp.mainMenu;
    for (CerfGlobalMenuItem* item in top_items) {
        const NSInteger at = [main indexOfItem:item];
        if (at >= 0) [main removeItemAtIndex:at];
        item.submenu.delegate = nil;
    }
    for (int index = 0; index < static_cast<int>(keys.size()); ++index) RemoveAppItems(index);
    [top_items release];
    [fillers release];
    [picks release];
    [app_items release];
}

void GlobalMenuBar::Native::Install() {
    NSMenu* main = NSApp.mainMenu;
    for (NSInteger i = main.numberOfItems - 1; i >= 0; --i) {
        if ([[main itemAtIndex:i] isKindOfClass:[CerfGlobalMenuItem class]]) [main removeItemAtIndex:i];
    }
    NSInteger at = std::min<NSInteger>(1, main.numberOfItems);
    for (CerfGlobalMenuItem* item in top_items) [main insertItem:item atIndex:at++];
}

void GlobalMenuBar::Native::Fill(int index, NSMenu* menu) {
    const QVariantList entries = source.Menu(index, keys[static_cast<size_t>(index)]);
    [menu removeAllItems];
    RemoveAppItems(index);
    Append(menu, entries, index, Blocked());
}

void GlobalMenuBar::Native::Pick(int index, NSInteger tag) {
    QObject*  key     = keys[static_cast<size_t>(index)];
    const int pick_id = static_cast<int>(tag);
    QMetaObject::invokeMethod(&bar, [this, key, pick_id] { source.MenuPicked(key, pick_id); }, Qt::QueuedConnection);
}

void GlobalMenuBar::Native::Append(NSMenu* menu, const QVariantList& entries, int index, bool blocked) {
    for (const QVariant& value : entries) {
        const QVariantMap entry = value.toMap();
        if (entry.value(QStringLiteral("separator")).toBool()) {
            AddSeparator(menu);
            continue;
        }
        if (entry.value(QStringLiteral("role")).toInt() != static_cast<int>(cerffrontend::MenuRole::kNone)) {
            PlaceInAppMenu(entry, index, blocked);
            continue;
        }
        const QVariantList row = entry.value(QStringLiteral("row")).toList();
        if (!row.isEmpty()) {
            [menu addItem:RowItem(row, index, blocked)];
            continue;
        }
        NSString*          title   = ItemTitle(entry.value(QStringLiteral("text")).toString());
        NSMenuItem*        item    = [[[NSMenuItem alloc] initWithTitle:title action:nil keyEquivalent:@""] autorelease];
        const QVariantList submenu = entry.value(QStringLiteral("submenu")).toList();
        if (submenu.isEmpty()) {
            Arm(item, entry.value(QStringLiteral("id")).toInt(), picks[static_cast<NSUInteger>(index)], blocked);
            item.state = entry.value(QStringLiteral("checked")).toBool() ? NSControlStateValueOn : NSControlStateValueOff;
        } else {
            NSMenu* sub          = [[[NSMenu alloc] initWithTitle:title] autorelease];
            sub.autoenablesItems = NO;
            Append(sub, submenu, index, blocked);
            item.submenu = sub;
            item.enabled = entry.value(QStringLiteral("enabled")).toBool() && !blocked;
        }
        [menu addItem:item];
    }
    DropTrailingSeparator(menu);
}

NSMenuItem* GlobalMenuBar::Native::RowItem(const QVariantList& buttons, int index, bool blocked) {
    NSStackView* row = [[[NSStackView alloc] init] autorelease];
    row.orientation  = NSUserInterfaceLayoutOrientationHorizontal;
    row.distribution = NSStackViewDistributionFillEqually;
    row.spacing      = 0;
    for (const QVariant& value : buttons) {
        const QVariantMap b      = value.toMap();
        NSButton*         button = [NSButton buttonWithImage:RowIcon(b.value(QStringLiteral("icon")).toString())
                                                  target:nil
                                                  action:nil];
        button.bezelStyle                      = NSBezelStyleAccessoryBarAction;
        button.showsBorderOnlyWhileMouseInside = YES;
        button.toolTip                         = b.value(QStringLiteral("text")).toString().toNSString();
        button.accessibilityLabel              = button.toolTip;
        Arm(button, b.value(QStringLiteral("id")).toInt(), picks[static_cast<NSUInteger>(index)], blocked);
        [row addArrangedSubview:button];
    }
    row.frame            = NSMakeRect(0, 0, row.fittingSize.width, row.fittingSize.height);
    row.autoresizingMask = NSViewWidthSizable;
    NSMenuItem* item     = [[[NSMenuItem alloc] initWithTitle:@"" action:nil keyEquivalent:@""] autorelease];
    item.view            = row;
    return item;
}

void GlobalMenuBar::Native::PlaceInAppMenu(const QVariantMap& entry, int index, bool blocked) {
    NSMenu*       app   = [NSApp.mainMenu itemAtIndex:0].submenu;
    const bool    about = entry.value(QStringLiteral("role")).toInt() == static_cast<int>(cerffrontend::MenuRole::kAbout);
    const QString text  = about ? QCoreApplication::translate("MAC_APPLICATION_MENU", "About %1")
                                      .arg(QStringLiteral(CERF_PRODUCT_NAME))
                                : QCoreApplication::translate("MAC_APPLICATION_MENU", "Preferences...");
    auto*         item  = [[[NSMenuItem alloc] initWithTitle:text.toNSString() action:nil
                                            keyEquivalent:about ? @"" : @","] autorelease];
    [app insertItem:item atIndex:about ? 0 : FirstSeparator(app) + 1];
    Arm(item, entry.value(QStringLiteral("id")).toInt(), picks[static_cast<NSUInteger>(index)], blocked);
    [app_items[static_cast<NSUInteger>(index)] addObject:item];
}

void GlobalMenuBar::Native::RemoveAppItems(int index) {
    NSMutableArray* items = app_items[static_cast<NSUInteger>(index)];
    for (NSMenuItem* item in items) [item.menu removeItem:item];
    [items removeAllObjects];
}

GlobalMenuBar::GlobalMenuBar(QWindow& window, MenuSource& source)
    : QObject(&window), native_(std::make_unique<Native>(window, source, *this)) {}

GlobalMenuBar::~GlobalMenuBar() = default;
