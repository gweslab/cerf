#include "property_preview.h"

#include "board_catalog.h"
#include "cpu_config_catalog.h"
#include "device_form_rules.h"
#include "filesystem_path.h"
#include "property_fields.h"
#include "property_options.h"
#include "property_sheet.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config_keys.h>

#include <QVariantMap>

REGISTER_SERVICE(PropertyPreview);

namespace {

namespace pf = persist_field;
namespace sf = sheet_field;
namespace sp = sheet_page;

QVariant Row(const QString& key, const QString& value) { return QVariantList{key, value}; }

QString OnText(bool on) { return on ? QStringLiteral("On") : QStringLiteral("Off"); }

QVariant ValueAt(const Json& data, const char* key) {
    const auto it = data.find(key);
    return it == data.end() ? QVariant() : JsonToVariant(*it);
}

QString FileShown(const QString& value) {
    if (value.isEmpty()) return QStringLiteral("-");
    return PathDisplayName(value);
}

}

QVariantList PropertyPreview::Blocks(const PropertySheet& sheet) const {
    auto&        catalog = emu_.Get<BoardCatalog>();
    QVariantList out;
    for (const QVariant& entry : sheet.Pages()) {
        const QVariantMap page = entry.toMap();
        const QString     key  = page.value(QStringLiteral("key")).toString();
        QVariantList      rows;
        if (key == QLatin1String(sp::kBoard))               rows = BoardRows(sheet);
        else if (key == QLatin1String(sp::kGuestAdditions)) rows = GuestAdditionsRows(sheet);
        else if (key == QLatin1String(sp::kDisplay))        rows = DisplayRows(sheet);
        else if (key == QLatin1String(sp::kCpuConfig))      rows = CpuRows(sheet);
        else if (key == QLatin1String(sp::kEmulator))       rows = EmulatorRows(sheet);
        out.append(QVariantMap{
            {QStringLiteral("key"), key},
            {QStringLiteral("title"), page.value(QStringLiteral("title"))},
            {QStringLiteral("rows"), rows},
            {QStringLiteral("warning"),
             catalog.SupportWarning(key == QLatin1String(sp::kBoard) ? sheet.BoardId() : QString())}});
    }
    return out;
}

QVariantList PropertyPreview::BoardRows(const PropertySheet& sheet) const {
    const QString board_id = sheet.BoardId();
    const Json&   data     = sheet.Data();
    const QString rom      = QString::fromLatin1(sf::kRom);
    const QString storage  = QString::fromLatin1(sf::kStorage);
    const QVariantMap files{{rom, ValueAt(data, sf::kRom)}, {storage, ValueAt(data, sf::kStorage)}};
    QVariantList rows{
        Row(QStringLiteral("Board"), emu_.Get<BoardCatalog>().BoardLabel(board_id, QStringLiteral("-")))};
    for (const FormFile& file : emu_.Get<DeviceFormRules>().FormFiles(board_id, files))
        rows.append(Row(file.name, FileShown(file.value)));
    return rows;
}

QVariantList PropertyPreview::GuestAdditionsRows(const PropertySheet& sheet) const {
    const Json&  data = sheet.Data();
    QVariantList rows{Row(QStringLiteral("Status"),
                          sheet.GuestAdditionsOn() ? QStringLiteral("Enabled") : QStringLiteral("Disabled"))};
    if (!sheet.GuestAdditionsOn()) return rows;
    auto&         options = emu_.Get<PropertyOptions>();
    const QString share   = sheet.ShareFolder();
    if (!share.isEmpty()) {
        rows.append(Row(QStringLiteral("Share folder"), LocationName(share)));
        rows.append(Row(QStringLiteral("Mount point"), options.MountPointPath(sheet.MountPoint())));
    }
    if (data.contains(pf::kWidth))
        rows.append(Row(QStringLiteral("Display resolution"),
                        options.ResolutionLabel(ValueAt(data, pf::kWidth), ValueAt(data, pf::kHeight), sheet.AutoSize())));
    if (data.contains(pf::kBpp))
        rows.append(Row(QStringLiteral("Color depth"), options.BppLabel(ValueAt(data, pf::kBpp), sheet.AutoDepth())));
    if (data.contains(pf::kDpi)) rows.append(Row(QStringLiteral("DPI"), options.DpiLabel(ValueAt(data, pf::kDpi))));
    if (data.contains(pf::kFontSize))
        rows.append(Row(QStringLiteral("Font size"), options.FontSizeLabel(ValueAt(data, pf::kFontSize))));
    if (data.contains(pf::kClearType))
        rows.append(Row(QStringLiteral("ClearType"), options.CleartypeLabel(ValueAt(data, pf::kClearType))));
    if (const QString scheme = JsonText(data, pf::kColorScheme); !scheme.isEmpty())
        rows.append(Row(QStringLiteral("Color scheme"), options.ColorSchemeLabel(scheme)));
    return rows;
}

QVariantList PropertyPreview::DisplayRows(const PropertySheet& sheet) const {
    const Json& data    = sheet.Data();
    auto&       options = emu_.Get<PropertyOptions>();
    return {Row(QStringLiteral("Display resolution"),
                options.ResolutionLabel(ValueAt(data, pf::kWidth), ValueAt(data, pf::kHeight), sheet.AutoSize())),
            Row(QStringLiteral("Color depth"), options.BppLabel(ValueAt(data, pf::kBpp), 0))};
}

QVariantList PropertyPreview::CpuRows(const PropertySheet& sheet) const {
    const QString     board_id  = sheet.BoardId();
    const QVariantMap overrides = sheet.BoardCpuOverrides();
    auto&             options   = emu_.Get<PropertyOptions>();
    auto&             cpu       = emu_.Get<CpuConfigCatalog>();
    QVariantList      rows{
        Row(QStringLiteral("CPU rate multiplier"),
            options.MultiplierLabel(options.MultiplierChoice(ValueAt(sheet.Data(), cerfcore::config_key::kCpuRateMultiplier)))),
        Row(QStringLiteral("Preset"), cpu.PresetLabel(board_id, overrides))};
    for (const auto& [name, value] : cpu.OverrideRows(board_id, overrides)) rows.append(Row(name, value));
    return rows;
}

QVariantList PropertyPreview::EmulatorRows(const PropertySheet& sheet) const {
    const Json& data    = sheet.Data();
    auto&       options = emu_.Get<PropertyOptions>();
    QVariantList rows{Row(QStringLiteral("Throttle multiplier"),
                          options.MultiplierLabel(
                              options.MultiplierChoice(ValueAt(data, cerfcore::config_key::kThrottleMultiplier))))};
    if (sheet.FullScreenSetting()) rows.append(Row(QStringLiteral("Borderless full screen"), OnText(sheet.FullScreen())));
    rows.append(Row(QStringLiteral("Detach internet connection"), OnText(!sheet.NetworkEnabled())));
    if (sheet.DoubleTapHelperSetting())
        rows.append(Row(QStringLiteral("Double-tap helper"), OnText(sheet.DoubleTapHelper())));
    return rows;
}
