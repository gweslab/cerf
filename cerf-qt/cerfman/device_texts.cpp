#include "device_texts.h"

#include "board_catalog.h"
#include "byte_size_text.h"
#include "text_compare.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_meta_label.h>

#include <QStringList>

#include <algorithm>

REGISTER_SERVICE(DeviceTexts);

namespace {

bool OsNameHasVersion(const QString& name, int major, int minor) {
    return cerfcore::OsNameHasVersion(name.toStdString(), major, minor);
}

}

int DeviceTexts::DeviceYear(const DeviceBundle& device) const {
    return emu_.Get<BoardCatalog>().DeviceYear(device.meta.board_id);
}

int DeviceTexts::BoardTier(const DeviceBundle& device) const {
    return BoardCatalog::NameTier(emu_.Get<BoardCatalog>().DisplayName(device.meta.board_id));
}

QString DeviceTexts::GroupName(const DeviceBundle& device) const {
    const QString board = emu_.Get<BoardCatalog>().DisplayName(device.meta.board_id);
    return device.meta.DeviceNameOr(board.isEmpty() ? device.name : board);
}

QString DeviceTexts::DeviceLabel(const DeviceBundle& device) const {
    const QString display = GroupName(device);
    const int     year    = DeviceYear(device);
    return year > 0 ? QStringLiteral("%1 (%2)").arg(display, QString::number(year)) : display;
}

QString DeviceTexts::OsLabel(const DeviceBundle& device) const {
    const DeviceMeta& meta     = device.meta;
    const QString     name     = meta.os_name.trimmed();
    const QString     language = meta.os_language.trimmed();
    QStringList       paren;
    const QString     ce = OsCeVersion(device);
    if (!ce.isEmpty()) paren.append(ce);
    if (!language.isEmpty()) paren.append(language);
    if (meta.os_year) paren.append(QString::number(meta.os_year));
    const QString base = !name.isEmpty() ? name : paren.isEmpty() ? QString() : QStringLiteral("Unknown OS");
    return paren.isEmpty() ? base : QStringLiteral("%1 (%2)").arg(base, paren.join(QStringLiteral(", ")));
}

QString DeviceTexts::OsTitle(const DeviceBundle& device) const {
    const QString edition_name = device.meta.os_name.trimmed();
    const QString edition      = edition_name.isEmpty() ? DeviceLabel(device) : edition_name;
    QStringList   parts{edition, device.meta.os_language.trimmed()};
    parts.removeAll(QString());
    return parts.join(QStringLiteral("  ·  "));
}

QString DeviceTexts::OsCeVersion(const DeviceBundle& device) const {
    const DeviceMeta& meta = device.meta;
    if (OsNameHasVersion(meta.os_name, meta.os_ver_major, meta.os_ver_minor)) return QString();
    return meta.CeVersion();
}

QString DeviceTexts::CardTitle(const DeviceBundle& device) const {
    return device.meta.name.isEmpty() ? OsTitle(device) : device.meta.name;
}

QString DeviceTexts::CardSubtitle(const DeviceBundle& device) const {
    QStringList parts;
    if (device.meta.name.isEmpty()) parts.append(device.meta.os_notes);
    parts.append(OsCeVersion(device));
    parts.removeAll(QString());
    return parts.join(QStringLiteral("  ·  "));
}

QString DeviceTexts::PanelDetail(const DeviceBundle& device) const {
    const int   year = device.meta.os_year;
    QStringList parts{year ? QString::number(year) : QString(), emu_.Get<BoardCatalog>().SocLabel(device.meta.board_id),
                      FormatSize(device.remote ? device.remote->unpacked_size : device.rom_size)};
    parts.removeAll(QString());
    return parts.join(QStringLiteral("  ·  "));
}

QStringList DeviceTexts::SearchFields(const DeviceBundle& device) const {
    auto&       boards = emu_.Get<BoardCatalog>();
    QStringList parts{device.meta.name,
                      DeviceLabel(device),
                      OsLabel(device),
                      boards.DisplayName(device.meta.board_id),
                      boards.SocLabel(device.meta.board_id),
                      device.StateLabel(),
                      device.name};
    parts.append(device.meta.os_notes);
    for (const PackageStatus& package : device.packages) parts.append(package.remote.name);
    return parts;
}

GroupKey DeviceTexts::BoardGroupKey(const DeviceBundle& device) const {
    return {BoardTier(device), SortText(emu_.Get<BoardCatalog>().DisplayName(device.meta.board_id))};
}

GroupKey DeviceTexts::DeviceGroupKey(const DeviceBundle& device) const {
    return {BoardTier(device), SortText(GroupName(device))};
}

SortKey DeviceTexts::DeviceSortKey(const DeviceBundle& device) const {
    const DeviceMeta& meta            = device.meta;
    const bool        version_missing = meta.os_ver_major == 0 && meta.os_ver_minor == 0;
    const QString     os              = SortText(meta.os_name);
    const int         year            = DeviceYear(device);
    return {SortText(device.DeviceName()),
            os.isEmpty(),
            os,
            version_missing,
            meta.os_ver_major,
            meta.os_ver_minor,
            year == 0,
            year,
            SortText(device.name)};
}

void DeviceTexts::SortForCards(std::vector<DeviceBundle>& devices) const {
    std::stable_sort(devices.begin(), devices.end(), [this](const DeviceBundle& a, const DeviceBundle& b) {
        return std::make_tuple(BoardGroupKey(a), SortText(DeviceLabel(a)), DeviceSortKey(a)) <
               std::make_tuple(BoardGroupKey(b), SortText(DeviceLabel(b)), DeviceSortKey(b));
    });
}
