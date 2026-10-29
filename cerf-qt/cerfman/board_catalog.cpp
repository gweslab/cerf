#include "board_catalog.h"

#include "board_order_text.h"
#include "text_compare.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cpu_arch_name.h>

#include <algorithm>
#include <map>
#include <vector>

REGISTER_SERVICE(BoardCatalog);

namespace {

using cerfcore::BoardDatabase;
using cerfcore::DbBoard;
using cerfcore::SupportLevel;

std::pair<int, QString> BoardSortKey(const QString& name) {
    return {BoardCatalog::NameTier(name), SortText(name)};
}

QString LevelLabel(SupportLevel level) {
    switch (level) {
        case SupportLevel::BootableFull:    return QStringLiteral("Bootable; Full support");
        case SupportLevel::BootablePartial: return QStringLiteral("Bootable; Partial support");
        case SupportLevel::UnknownPartial:  return QStringLiteral("Unknown; Partial support");
        case SupportLevel::NoSupport:       return QStringLiteral("Unbootable; No support");
    }
    return QString();
}

}

int BoardCatalog::NameTier(const QString& board_name) {
    const QString text = SortText(board_name);
    if (text.isEmpty()) return 0;
    return text.startsWith(QLatin1String(CERF_LAST_BOARD_TIER_PREFIX)) ? 2 : 1;
}

const DbBoard* BoardCatalog::Find(const QString& board_id) const {
    return emu_.Get<BoardDatabase>().FindBoard(board_id.toStdString());
}

std::optional<QSize> BoardCatalog::PanelSize(const QString& board_id) const {
    const DbBoard* board = Find(board_id);
    if (!board || !board->lcd_panel_size) return std::nullopt;
    return QSize(static_cast<int>(board->lcd_panel_size->width),
                 static_cast<int>(board->lcd_panel_size->height));
}

std::optional<cerfcore::CpuArch> BoardCatalog::Arch(const QString& board_id) const {
    const DbBoard* board = Find(board_id);
    if (!board) return std::nullopt;
    return emu_.Get<BoardDatabase>().SocArch(board->soc_id);
}

bool BoardCatalog::Runs(const QString& board_id) const {
    const DbBoard* board = Find(board_id);
    return board && board->runs;
}

std::optional<bool> BoardCatalog::FeatureSupport(const QString& board_id, std::string_view feature_id) const {
    const DbBoard* board = Find(board_id);
    if (!board) return std::nullopt;
    for (const auto& f : board->features)
        if (f.feature_id == feature_id) return f.supported;
    return std::nullopt;
}

bool BoardCatalog::FeatureAllowed(const QString& board_id, std::string_view feature_id) const {
    return FeatureSupport(board_id, feature_id).value_or(true);
}

std::vector<const cerfcore::DbDeviceFeature*> BoardCatalog::UnsupportedFeatures(const QString& board_id) const {
    std::vector<const cerfcore::DbDeviceFeature*> out;
    for (const auto& feature : emu_.Get<BoardDatabase>().DeviceFeatures())
        if (FeatureSupport(board_id, feature.id) == false) out.push_back(&feature);
    return out;
}

QString BoardCatalog::MountPointDefault() const {
    return QString::fromStdString(emu_.Get<BoardDatabase>().GaSharedFolderMountPoint());
}

QString BoardCatalog::DisplayName(const QString& board_id) const {
    const DbBoard* board = Find(board_id);
    return board ? QString::fromStdString(board->name) : QString();
}

QString BoardCatalog::BoardLabel(const QString& board_id, const QString& empty_text) const {
    const QString name = DisplayName(board_id);
    if (!name.isEmpty()) return name;
    return board_id.isEmpty() ? empty_text : board_id;
}

QString BoardCatalog::FamilyName(const QString& board_id) const {
    const DbBoard* board = Find(board_id);
    return board ? QString::fromStdString(emu_.Get<BoardDatabase>().BoardFamily(board->family_id).name) : QString();
}

QString BoardCatalog::SocLabel(const QString& board_id) const {
    const DbBoard* board = Find(board_id);
    if (!board) return QString();
    auto&       db  = emu_.Get<BoardDatabase>();
    const auto& soc = db.Soc(board->soc_id);
    return QStringLiteral("%1 (%2)").arg(QString::fromStdString(soc.name),
                                         QString::fromStdString(db.SocFamily(soc.family_id).name));
}

QString BoardCatalog::ArchName(const QString& board_id) const {
    const std::optional<cerfcore::CpuArch> arch = Arch(board_id);
    return arch ? QString::fromLatin1(cerfcore::CpuArchName(*arch)) : QString();
}

QVariantMap BoardCatalog::SupportWarning(const QString& board_id) const {
    const auto warning = [](bool danger, const QString& text) {
        return QVariantMap{{QStringLiteral("danger"), danger}, {QStringLiteral("text"), text}};
    };
    if (board_id.isEmpty()) return warning(false, QString());
    const DbBoard* board = Find(board_id);
    if (!board) return warning(true, QStringLiteral("CERF does not know this board."));
    switch (board->support_level) {
        case SupportLevel::BootableFull:
            return warning(false, QString());
        case SupportLevel::NoSupport:
            return warning(true, LevelLabel(board->support_level));
        case SupportLevel::BootablePartial:
        case SupportLevel::UnknownPartial:
            return warning(false, LevelLabel(board->support_level));
    }
    return warning(false, QString());
}

QStringList BoardCatalog::Notes(const QString& board_id) const {
    QStringList out;
    if (const DbBoard* board = Find(board_id))
        for (const auto& note : board->notes) out.append(QString::fromStdString(note));
    return out;
}

bool BoardCatalog::ConfigurableScreen(const QString& board_id) const {
    const DbBoard* board = Find(board_id);
    return board && board->configurable_screen;
}

int BoardCatalog::GaColorDepth(const QString& board_id) const {
    const DbBoard* board = Find(board_id);
    return static_cast<int>(board ? board->ga_color_depth : cerfcore::kDefaultGaColorDepth);
}

int BoardCatalog::DeviceYear(const QString& board_id) const {
    const DbBoard* board = Find(board_id);
    return board ? static_cast<int>(board->device_year) : 0;
}

QString BoardCatalog::FirstRunningBoard() const {
    const auto boards = emu_.Get<BoardDatabase>().Boards();
    return QString::fromStdString(
        std::find_if(boards.begin(), boards.end(), [](const DbBoard& board) { return board.runs; })->id);
}

QVariantMap BoardCatalog::GroupHardware(const QStringList& board_ids) const {
    QStringList socs;
    QStringList arches;
    for (const QString& board_id : board_ids) {
        const QString soc  = SocLabel(board_id);
        const QString arch = ArchName(board_id);
        if (!soc.isEmpty() && !socs.contains(soc)) socs.append(soc);
        if (!arch.isEmpty() && !arches.contains(arch)) arches.append(arch);
    }
    return QVariantMap{{QStringLiteral("soc"), socs.join(QStringLiteral(" / "))}, {QStringLiteral("arches"), arches}};
}

QVariantList BoardCatalog::GroupedBoards(bool show_unsupported, bool show_unknown,
                                         const QString& query) const {
    auto& db = emu_.Get<BoardDatabase>();
    std::map<std::string, std::vector<const DbBoard*>> members;
    for (const auto& board : db.Boards()) {
        if (!show_unknown && board.support_level == SupportLevel::UnknownPartial) continue;
        if (!show_unsupported && board.support_level == SupportLevel::NoSupport) continue;
        const QString id = QString::fromStdString(board.id);
        const QStringList fields{QString::fromStdString(board.name), id, FamilyName(id), SocLabel(id),
                                 LevelLabel(board.support_level)};
        if (!MatchesQuery(fields, query)) continue;
        members[board.family_id].push_back(&board);
    }
    std::vector<const cerfcore::DbBoardFamily*> families;
    for (const auto& family : db.Families())
        if (members.count(family.id)) families.push_back(&family);
    std::stable_sort(families.begin(), families.end(), [](auto* a, auto* b) {
        return SortTextLess(QString::fromStdString(a->name), QString::fromStdString(b->name));
    });
    QVariantList out;
    for (const auto* family : families) {
        auto& boards = members[family->id];
        std::stable_sort(boards.begin(), boards.end(), [](auto* a, auto* b) {
            return BoardSortKey(QString::fromStdString(a->name)) < BoardSortKey(QString::fromStdString(b->name));
        });
        QVariantList rows;
        QStringList  ids;
        for (const DbBoard* board : boards) {
            const QString id = QString::fromStdString(board->id);
            ids.append(id);
            rows.append(QVariantMap{{QStringLiteral("id"), id},
                                    {QStringLiteral("name"), QString::fromStdString(board->name)},
                                    {QStringLiteral("support"), LevelLabel(board->support_level)}});
        }
        QVariantMap group = GroupHardware(ids);
        group.insert(QStringLiteral("family"), QString::fromStdString(family->name));
        group.insert(QStringLiteral("boards"), rows);
        out.append(group);
    }
    return out;
}
