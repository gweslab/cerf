#include "qt_screen_pixels.h"

#include "qt_unscaled_screen_pixels.h"
#include "desktop/wayland_registry_scan.h"
#include "xdg-output-unstable-v1-client-protocol.h"

#include <cerfcore/core/log.h>

#include <QGuiApplication>
#include <QScreen>
#include <QtGui/qguiapplication_platform.h>
#include <QtGui/qscreen_platform.h>

#include <wayland-client.h>
#include <xcb/randr.h>
#include <xcb/xcb.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <vector>

namespace {

QSize NoPixels(const QScreen& screen, const char* reason) {
    LOG(Caution, "ScreenPixels: screen '%s': %s\n", qUtf8Printable(screen.name()), reason);
    return kNoScreenPixels;
}

template <typename T>
std::unique_ptr<T, decltype(&std::free)> Owned(T* reply) {
    return std::unique_ptr<T, decltype(&std::free)>(reply, &std::free);
}

QString AtomName(xcb_connection_t* c, xcb_atom_t atom) {
    const auto reply = Owned(xcb_get_atom_name_reply(c, xcb_get_atom_name(c, atom), nullptr));
    if (!reply) return QString();
    return QString::fromLatin1(xcb_get_atom_name_name(reply.get()), xcb_get_atom_name_name_length(reply.get()));
}

QString FakeScreenName(int number) {
    QByteArray display = qgetenv("DISPLAY");
    const int  dot     = display.lastIndexOf('.');
    if (dot != -1) display.truncate(dot);
    return QString::fromLocal8Bit(display) + u'.' + QString::number(number);
}

bool MonitorRect(xcb_connection_t* c, xcb_window_t root, int number, const QString& wanted, QRect& out) {
    const auto reply = Owned(xcb_randr_get_monitors_reply(c, xcb_randr_get_monitors(c, root, 1), nullptr));
    if (!reply) return false;
    bool any = false;
    for (auto it = xcb_randr_get_monitors_monitors_iterator(reply.get()); it.rem; xcb_randr_monitor_info_next(&it)) {
        any                  = true;
        const QString atom   = AtomName(c, it.data->name);
        const QString name   = atom.isEmpty() ? FakeScreenName(number) : atom;
        if (name != wanted) continue;
        if (it.data->width != 0 && it.data->height != 0)
            out = QRect(it.data->x, it.data->y, it.data->width, it.data->height);
        return true;
    }
    return !any && FakeScreenName(number) == wanted;
}

bool OutputRect(xcb_connection_t* c, xcb_window_t root, int number, const QString& wanted, QRect& out) {
    const auto current = Owned(xcb_randr_get_screen_resources_current_reply(
        c, xcb_randr_get_screen_resources_current(c, root), nullptr));
    auto                resources = Owned<xcb_randr_get_screen_resources_reply_t>(nullptr);
    xcb_timestamp_t     timestamp = 0;
    xcb_randr_output_t* outputs   = nullptr;
    int                 count     = 0;
    if (current) {
        count = xcb_randr_get_screen_resources_current_outputs_length(current.get());
        if (count != 0) {
            timestamp = current->config_timestamp;
            outputs   = xcb_randr_get_screen_resources_current_outputs(current.get());
        } else {
            resources =
                Owned(xcb_randr_get_screen_resources_reply(c, xcb_randr_get_screen_resources(c, root), nullptr));
            if (resources) {
                timestamp = resources->config_timestamp;
                outputs   = xcb_randr_get_screen_resources_outputs(resources.get());
                count     = xcb_randr_get_screen_resources_outputs_length(resources.get());
            }
        }
    }
    const bool primary =
        count != 0 && Owned(xcb_randr_get_output_primary_reply(c, xcb_randr_get_output_primary(c, root), nullptr));
    bool any = false;
    for (int i = 0; primary && i < count; ++i) {
        const auto info =
            Owned(xcb_randr_get_output_info_reply(c, xcb_randr_get_output_info(c, outputs[i], timestamp), nullptr));
        if (!info || info->connection != XCB_RANDR_CONNECTION_CONNECTED || info->crtc == XCB_NONE) continue;
        any = true;
        const QString name = QString::fromUtf8(reinterpret_cast<const char*>(xcb_randr_get_output_info_name(info.get())),
                                               xcb_randr_get_output_info_name_length(info.get()));
        if (name != wanted) continue;
        const auto crtc =
            Owned(xcb_randr_get_crtc_info_reply(c, xcb_randr_get_crtc_info(c, info->crtc, info->timestamp), nullptr));
        if (crtc && crtc->width != 0 && crtc->height != 0) out = QRect(crtc->x, crtc->y, crtc->width, crtc->height);
        return true;
    }
    return !any && FakeScreenName(number) == wanted;
}

struct X11Screen {
    QRect        rect;
    xcb_window_t root = XCB_NONE;
};

std::optional<X11Screen> X11Locate(const QScreen& screen, xcb_connection_t* c) {
    const QString wanted = screen.name();
    int           minor  = -1;
    const xcb_query_extension_reply_t* randr = xcb_get_extension_data(c, &xcb_randr_id);
    if (randr != nullptr && randr->present) {
        const auto version = Owned(xcb_randr_query_version_reply(
            c, xcb_randr_query_version(c, XCB_RANDR_MAJOR_VERSION, XCB_RANDR_MINOR_VERSION), nullptr));
        if (version && (version->major_version > 1 || (version->major_version == 1 && version->minor_version >= 2)))
            minor = version->minor_version;
    }
    int number = 0;
    for (auto it = xcb_setup_roots_iterator(xcb_get_setup(c)); it.rem; xcb_screen_next(&it), ++number) {
        const QRect root(0, 0, it.data->width_in_pixels, it.data->height_in_pixels);
        QRect       found;
        const bool  matched = minor >= 5   ? MonitorRect(c, it.data->root, number, wanted, found)
                              : minor >= 2 ? OutputRect(c, it.data->root, number, wanted, found)
                                           : FakeScreenName(number) == wanted;
        if (matched) return X11Screen{found.isValid() ? found : root, it.data->root};
    }
    NoPixels(screen, "no X11 RandR monitor, output or screen carries its name");
    return std::nullopt;
}

QSize X11Pixels(const QScreen& screen, xcb_connection_t* c) {
    const std::optional<X11Screen> found = X11Locate(screen, c);
    return found ? found->rect.size() : kNoScreenPixels;
}

constexpr char kWorkArea[] = "_NET_WORKAREA";

std::optional<QRect> X11WorkArea(xcb_connection_t* c, xcb_window_t root) {
    const auto atom = Owned(xcb_intern_atom_reply(
        c, xcb_intern_atom(c, 1, static_cast<uint16_t>(std::strlen(kWorkArea)), kWorkArea), nullptr));
    if (!atom || atom->atom == XCB_NONE) return std::nullopt;
    const auto value = Owned(xcb_get_property_reply(
        c, xcb_get_property(c, 0, root, atom->atom, XCB_ATOM_CARDINAL, 0, 1024), nullptr));
    if (!value || value->type != XCB_ATOM_CARDINAL || value->format != 32 || value->value_len < 4) return std::nullopt;
    const auto* geom = static_cast<const uint32_t*>(xcb_get_property_value(value.get()));
    return QRect(static_cast<int>(geom[0]), static_cast<int>(geom[1]), static_cast<int>(geom[2]),
                 static_cast<int>(geom[3]));
}

QSize X11WorkAreaPixels(const QScreen& screen, xcb_connection_t* c) {
    const std::optional<X11Screen> found = X11Locate(screen, c);
    if (!found) return kNoScreenPixels;
    if (screen.virtualSiblings().size() > 1 && qEnvironmentVariableIsEmpty("QT_RELY_ON_NET_WORKAREA_ATOM"))
        return found->rect.size();
    const std::optional<QRect> work = X11WorkArea(c, found->root);
    return work ? (found->rect & *work).size() : found->rect.size();
}

struct WaylandOutput {
    uint32_t        global       = 0;
    uint32_t        version      = 0;
    wl_output*      output       = nullptr;
    zxdg_output_v1* xdg_output   = nullptr;
    bool            name_seen    = false;
    QString         name;
    QString         xdg_name;
    int32_t         transform    = WL_OUTPUT_TRANSFORM_NORMAL;
    QSize           mode;
};

struct WaylandGlobals {
    std::vector<std::unique_ptr<WaylandOutput>> outputs;
    zxdg_output_manager_v1*                     xdg_manager = nullptr;
};

QString WaylandOutputName(const WaylandOutput& entry) {
    if (!entry.name.isEmpty()) return entry.name;
    if (!entry.name_seen && !entry.xdg_name.isEmpty()) return entry.xdg_name;
    return QStringLiteral("Screen%1").arg(entry.global);
}

void OnGeometry(void* data, wl_output*, int32_t, int32_t, int32_t, int32_t, int32_t, const char*, const char*,
                int32_t transform) {
    static_cast<WaylandOutput*>(data)->transform = transform;
}

void OnMode(void* data, wl_output*, uint32_t flags, int32_t width, int32_t height, int32_t) {
    if (flags & WL_OUTPUT_MODE_CURRENT) static_cast<WaylandOutput*>(data)->mode = QSize(width, height);
}

void OnDone(void*, wl_output*) {}

void OnScale(void*, wl_output*, int32_t) {}

void OnName(void* data, wl_output*, const char* name) {
    auto* entry      = static_cast<WaylandOutput*>(data);
    entry->name_seen = true;
    entry->name      = QString::fromUtf8(name);
}

void OnDescription(void*, wl_output*, const char*) {}

const wl_output_listener kOutputListener = {OnGeometry, OnMode, OnDone, OnScale, OnName, OnDescription};

void OnXdgPosition(void*, zxdg_output_v1*, int32_t, int32_t) {}

void OnXdgSize(void*, zxdg_output_v1*, int32_t, int32_t) {}

void OnXdgDone(void*, zxdg_output_v1*) {}

void OnXdgName(void* data, zxdg_output_v1*, const char* name) {
    static_cast<WaylandOutput*>(data)->xdg_name = QString::fromUtf8(name);
}

void OnXdgDescription(void*, zxdg_output_v1*, const char*) {}

const zxdg_output_v1_listener kXdgOutputListener = {OnXdgPosition, OnXdgSize, OnXdgDone, OnXdgName, OnXdgDescription};

void OnGlobal(void* data, wl_registry* registry, uint32_t global, const char* interface, uint32_t version) {
    auto* globals = static_cast<WaylandGlobals*>(data);
    if (std::strcmp(interface, zxdg_output_manager_v1_interface.name) == 0) {
        globals->xdg_manager = static_cast<zxdg_output_manager_v1*>(
            wl_registry_bind(registry, global, &zxdg_output_manager_v1_interface, std::min(version, 3u)));
        return;
    }
    if (std::strcmp(interface, wl_output_interface.name) != 0) return;
    auto entry     = std::make_unique<WaylandOutput>();
    entry->global  = global;
    entry->version = std::min(version, 4u);
    entry->output  = static_cast<wl_output*>(wl_registry_bind(registry, global, &wl_output_interface, entry->version));
    wl_output_add_listener(entry->output, &kOutputListener, entry.get());
    globals->outputs.push_back(std::move(entry));
}

QSize WaylandPixels(const QScreen& screen, wl_display* display) {
    WaylandGlobals      globals;
    WaylandRegistryScan scan(display, &OnGlobal, &globals);
    bool                read = scan.Roundtrip();
    if (read && globals.xdg_manager != nullptr) {
        for (const auto& entry : globals.outputs) {
            entry->xdg_output = zxdg_output_manager_v1_get_xdg_output(globals.xdg_manager, entry->output);
            zxdg_output_v1_add_listener(entry->xdg_output, &kXdgOutputListener, entry.get());
        }
    }
    read = read && scan.Roundtrip();
    QSize found;
    for (const auto& entry : globals.outputs) {
        if (WaylandOutputName(*entry) != screen.name()) continue;
        found = (entry->transform & 1) != 0 ? entry->mode.transposed() : entry->mode;
    }
    for (const auto& entry : globals.outputs) {
        if (entry->xdg_output != nullptr) zxdg_output_v1_destroy(entry->xdg_output);
        if (entry->version >= WL_OUTPUT_RELEASE_SINCE_VERSION) wl_output_release(entry->output);
        else                                                   wl_output_destroy(entry->output);
    }
    if (globals.xdg_manager != nullptr) zxdg_output_manager_v1_destroy(globals.xdg_manager);
    if (!read) return NoPixels(screen, "the Wayland roundtrip failed");
    if (!found.isValid()) return NoPixels(screen, "no Wayland output carries its name and a current mode");
    return found;
}

xcb_connection_t* XcbConnection() {
    const auto* x11 = qGuiApp->nativeInterface<QNativeInterface::QX11Application>();
    return x11 != nullptr ? x11->connection() : nullptr;
}

}

QSize ScreenPixels(const QScreen& screen) {
    if (xcb_connection_t* c = XcbConnection()) return X11Pixels(screen, c);
    const auto* wayland = qGuiApp->nativeInterface<QNativeInterface::QWaylandApplication>();
    if (wayland == nullptr) return UnscaledScreenPixels(screen);
    if (screen.nativeInterface<QNativeInterface::QWaylandScreen>() == nullptr) return kNoScreenPixels;
    return WaylandPixels(screen, wayland->display());
}

QSize ScreenWorkAreaPixels(const QScreen& screen) {
    if (xcb_connection_t* c = XcbConnection()) return X11WorkAreaPixels(screen, c);
    if (qGuiApp->nativeInterface<QNativeInterface::QWaylandApplication>() != nullptr) return ScreenPixels(screen);
    return UnscaledWorkAreaPixels(screen);
}
