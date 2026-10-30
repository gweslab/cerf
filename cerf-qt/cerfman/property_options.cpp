#include "property_options.h"

#include "emulation_speed.h"
#include "json_file.h"
#include "whole_number.h"

#include "../dpi_scale.h"

#include <cerfcore/core/board_database.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config_keys.h>
#include <cerfcore/core/hud_database.h>
#include <cerfcore/core/share_folder_mount_name.h>
#include <cerfcore/peripherals/cerf_virt/guest_color_schemes.h>

#include <QStringList>

#include <array>
#include <limits>
#include <optional>
#include <string_view>

REGISTER_SERVICE(PropertyOptions);

namespace {

struct Resolution {
    int         width;
    int         height;
    const char* name;
};

constexpr Resolution kResolutions[] = {
    {176, 220, "QCIF+"},
    {240, 320, "QVGA"},        {320, 240, "QVGA"},       {320, 480, "HVGA"},
    {480, 320, "HVGA"},        {640, 480, "VGA"},        {480, 640, "VGA"},
    {800, 480, "WVGA"},        {480, 800, "WVGA"},       {854, 480, "FWVGA"},
    {800, 600, "SVGA"},        {600, 800, "SVGA"},       {1024, 600, "WSVGA"},
    {1024, 768, "XGA"},        {768, 1024, "XGA"},       {1280, 720, "HD 720p"},
    {1280, 800, "WXGA"},       {1366, 768, "HD"},        {1280, 1024, "SXGA"},
    {1440, 900, "WXGA+"},      {1600, 900, "HD+"},       {1680, 1050, "WSXGA+"},
    {1600, 1200, "UXGA"},      {1920, 1080, "FHD 1080p"}, {1920, 1200, "WUXGA"},
    {2560, 1440, "QHD 1440p"}, {2560, 1600, "WQXGA"},    {3440, 1440, "UW-QHD"},
    {3840, 2160, "4K UHD"},
};

constexpr std::array<int, 12> kDpiScalePercents    = {100, 125, 150, 175, 200, 225,
                                                      250, 300, 350, 400, 450, 500};
constexpr int                 kFontSizeMin         = 6;
constexpr int                 kFontSizeMax         = 48;
constexpr QChar               kGuestRootSeparator  = u'\\';

constexpr std::array<int, 4> kBppChoices = {8, 16, 24, 32};

struct ScalePreset {
    const char*  name;
    ScaleSetting setting;
};

constexpr std::array<ScalePreset, 3> kScalePresets = {{
    {"Standard", {cerffrontend::kDefaultDpi, 12, true}},
    {"2K", {cerffrontend::kDefaultDpi * 3 / 2, 18, true}},
    {"4K", {cerffrontend::kDefaultDpi * 2, 24, true}}}};

bool IsNumber(const QVariant& value) {
    switch (value.typeId()) {
        case QMetaType::Int:
        case QMetaType::UInt:
        case QMetaType::LongLong:
        case QMetaType::ULongLong:
        case QMetaType::Double:
        case QMetaType::Float:
            return true;
        default:
            return false;
    }
}

bool IsInteger(const QVariant& value) {
    if (!IsNumber(value)) return false;
    return IsWholeNumber(value.toDouble());
}

QString Number(double value) { return QString::number(value, 'g', 6); }

QString Utf8(std::string_view text) { return QString::fromUtf8(text.data(), qsizetype(text.size())); }

QString BppText(int bpp) { return QStringLiteral("%1bpp").arg(bpp); }

QString SizeText(int width, int height) { return QStringLiteral("%1x%2").arg(width).arg(height); }

QString DpiText(int dpi) { return QStringLiteral("%1 DPI").arg(dpi); }

}

QString PropertyOptions::CustomChoice() const { return QStringLiteral("Custom…"); }

QVariantList PropertyOptions::ResolutionChoices() const {
    QVariantList out{NullVariant()};
    for (const Resolution& r : kResolutions) out.append(QVariant(QVariantList{r.width, r.height}));
    return out;
}

QString PropertyOptions::ResolutionLabel(const QVariant& width, const QVariant& height,
                                         const QSize& auto_size) const {
    if (!IsInteger(width) || !IsInteger(height))
        return QStringLiteral("Auto - %1").arg(SizeText(auto_size.width(), auto_size.height()));
    const int w    = width.toInt();
    const int h    = height.toInt();
    QString   name = QStringLiteral("Custom");
    for (const Resolution& r : kResolutions)
        if (r.width == w && r.height == h) name = QString::fromLatin1(r.name);
    return QStringLiteral("%1 - %2").arg(name, SizeText(w, h));
}

QString PropertyOptions::ResolutionChoiceLabel(const QVariant& choice, const QSize& auto_size) const {
    const QVariantList size = choice.toList();
    if (size.size() != 2) return ResolutionLabel(QVariant(), QVariant(), auto_size);
    return ResolutionLabel(size.at(0), size.at(1), auto_size);
}

QVariantList PropertyOptions::DpiChoices() const {
    QVariantList out{NullVariant()};
    for (int percent : kDpiScalePercents) out.append(cerffrontend::kDefaultDpi * percent / 100);
    return out;
}

QString PropertyOptions::DpiLabel(const QVariant& dpi) const {
    if (!IsInteger(dpi)) return QStringLiteral("Default");
    const int    value   = dpi.toInt();
    const double percent = std::nearbyint(value * 100.0 / cerffrontend::kDefaultDpi);
    return QStringLiteral("%1% - %2").arg(QString::number(static_cast<int>(percent)), DpiText(value));
}

int PropertyOptions::DefaultDpi() const { return cerffrontend::kDefaultDpi; }

QVariantList PropertyOptions::FontSizeChoices() const {
    QVariantList out{NullVariant()};
    for (int size = kFontSizeMin; size <= kFontSizeMax; ++size) out.append(size);
    return out;
}

QString PropertyOptions::FontSizeLabel(const QVariant& size) const {
    return IsInteger(size) ? QString::number(size.toInt()) : QStringLiteral("Default");
}

QVariantList PropertyOptions::BppChoices() const {
    QVariantList out{NullVariant()};
    for (int bpp : kBppChoices) out.append(bpp);
    return out;
}

QString PropertyOptions::BppLabel(const QVariant& value, int auto_depth) const {
    if (IsInteger(value)) return BppText(value.toInt());
    return auto_depth ? QStringLiteral("Auto - %1").arg(BppText(auto_depth)) : QStringLiteral("Auto");
}

QString PropertyOptions::BppHelpText() const {
    return QStringLiteral("Some values can break the guest. Keep the default value unless you have a reason to change "
                          "it.\n\n"
                          "• Auto - the depth that is known to work on this device.\n"
                          "• 8bpp - for Windows CE 2.0.\n"
                          "• 16bpp - works best for Windows CE 2.11 and 3.0.\n"
                          "• 24bpp - works for every Windows CE version.\n"
                          "• 32bpp - Windows CE 2.11 and later. It often breaks the rendering of guest apps.");
}

QVariantList PropertyOptions::CleartypeChoices() const { return {NullVariant(), true, false}; }

QString PropertyOptions::CleartypeLabel(const QVariant& value) const {
    if (value.typeId() != QMetaType::Bool) return QStringLiteral("Default");
    return value.toBool() ? QStringLiteral("Enabled") : QStringLiteral("Disabled");
}

QVariantList PropertyOptions::ColorSchemeKeys() const {
    QVariantList out{QString()};
    for (const auto& scheme : cerfcore::GuestColorSchemes()) out.append(Utf8(scheme.key));
    return out;
}

QString PropertyOptions::ColorSchemeLabel(const QString& key) const {
    if (key.isEmpty()) return QStringLiteral("Default");
    for (const auto& scheme : cerfcore::GuestColorSchemes())
        if (Utf8(scheme.key) == key) return Utf8(scheme.label);
    return key;
}

QVariantList PropertyOptions::HudChoices() const {
    QVariantList out{NullVariant(), QString::fromLatin1(cerfcore::config_key::kHudNone)};
    for (const cerfcore::DbHud& hud : emu_.Get<cerfcore::HudDatabase>().Huds()) out.append(Utf8(hud.id));
    return out;
}

QString PropertyOptions::HudLabel(const QVariant& value, const QString& board_id) const {
    const QString none = QStringLiteral("None");
    auto&         huds = emu_.Get<cerfcore::HudDatabase>();
    if (value.isNull()) {
        const cerfcore::DbBoard* board = emu_.Get<cerfcore::BoardDatabase>().FindBoard(board_id.toStdString());
        const cerfcore::DbHud*   hud   = board ? huds.AutoFor(board->id, board->family_id) : nullptr;
        return QStringLiteral("Auto - %1").arg(hud ? Utf8(hud->name) : none);
    }
    if (value.toString() == QLatin1String(cerfcore::config_key::kHudNone)) return none;
    const cerfcore::DbHud* hud = huds.Find(value.toString().toStdString());
    return hud ? Utf8(hud->name) : value.toString();
}

QVariantList PropertyOptions::ScalePresetIndexes() const {
    QVariantList out;
    for (int i = 0; i < static_cast<int>(kScalePresets.size()); ++i) out.append(i);
    return out;
}

QString PropertyOptions::ScalePresetLabel(int index) const {
    if (index < 0) return QStringLiteral("Custom");
    const ScalePreset& p = kScalePresets[size_t(index)];
    return QStringLiteral("%1 / %2").arg(QString::fromLatin1(p.name), DpiText(p.setting.dpi));
}

ScaleSetting PropertyOptions::ScalePresetAt(int index) const { return kScalePresets[size_t(index)].setting; }

int PropertyOptions::ScalePresetIndex(const QVariant& dpi, const QVariant& font_size,
                                      const QVariant& cleartype) const {
    if (!IsInteger(dpi) || !IsInteger(font_size) || cleartype.typeId() != QMetaType::Bool) return -1;
    int match = -1;
    for (int i = 0; i < static_cast<int>(kScalePresets.size()); ++i) {
        const ScaleSetting& s = kScalePresets[size_t(i)].setting;
        if (s.dpi == dpi.toInt() && s.font_size == font_size.toInt() && s.cleartype == cleartype.toBool())
            match = i;
    }
    return match;
}

QVariantList PropertyOptions::MultiplierChoices(const QString& key) const {
    QVariantList out;
    if (key == QLatin1String(cerfcore::config_key::kThrottleMultiplier)) out.append(0);
    for (const std::optional<double>& step : kMultiplierSteps) out.append(step ? QVariant(*step) : NullVariant());
    return out;
}

QVariant PropertyOptions::MultiplierChoice(const QVariant& value) const {
    if (!IsNumber(value) || value.toDouble() == kDefaultMultiplier) return NullVariant();
    return value;
}

QString PropertyOptions::MultiplierLabel(const QVariant& value) const {
    if (!IsNumber(value)) return QStringLiteral("Auto (%1)").arg(Number(kDefaultMultiplier));
    return Number(value.toDouble());
}

bool PropertyOptions::MountPointValid(const QString& name) const {
    return name.isEmpty() || cerfcore::IsValidShareFolderMountName(name.toStdString());
}

QString PropertyOptions::MountPointPath(const QString& name) const { return kGuestRootSeparator + name; }

QString PropertyOptions::MountPointName(const QString& path) const {
    return path.startsWith(kGuestRootSeparator) ? path.mid(1) : path;
}

int PropertyOptions::ConfigIntegerMaximum() const { return std::numeric_limits<int>::max(); }

QString PropertyOptions::MountPointInvalidMessage() const {
    QStringList invalid;
    for (char c : std::string_view(cerfcore::kShareFolderMountNameInvalidChars)) invalid.append(QChar::fromLatin1(c));
    return QStringLiteral("A mount point name can have up to %1 characters. It cannot contain "
                          "control characters or any of %2")
        .arg(qulonglong(cerfcore::kShareFolderMountNameMaxWchars))
        .arg(invalid.join(QLatin1Char(' ')));
}
