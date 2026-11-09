#include "board_config_catalog.h"

#include "board_catalog.h"

#include <cerfcore/core/cerf_emulator.h>

REGISTER_SERVICE(BoardConfigCatalog);

namespace {

bool Accepts(const cerfcore::DbBoardConfigSetting& setting, const QVariant& value) {
    return !value.isNull() && value.typeId() == QMetaType::QString && setting.Accepts(value.toString().toStdString());
}

QVariant StoredChoice(const QVariantMap& set, const QString& id) {
    return set.contains(id) ? set.value(id) : NullVariant();
}

}

std::span<const cerfcore::DbBoardConfigSetting> BoardConfigCatalog::SettingsFor(const QString& board_id) const {
    const cerfcore::DbBoard* board = emu_.Get<BoardCatalog>().Find(board_id);
    if (!board) return {};
    return board->config;
}

const cerfcore::DbBoardConfigSetting* BoardConfigCatalog::Setting(const QString& board_id,
                                                                  const QString& param_id) const {
    return cerfcore::FindBoardConfigSetting(SettingsFor(board_id), param_id.toStdString());
}

QVariantList BoardConfigCatalog::Params(const QString& board_id) const {
    const auto&  db = emu_.Get<cerfcore::BoardDatabase>();
    QVariantList out;
    for (const cerfcore::DbBoardConfigSetting& s : SettingsFor(board_id)) {
        QVariantList values{NullVariant()};
        for (const std::string& v : s.values) values.append(QString::fromStdString(v));
        out.append(QVariantMap{{QStringLiteral("board"), board_id},
                               {QStringLiteral("id"), QString::fromStdString(s.param_id)},
                               {QStringLiteral("name"), QString::fromStdString(db.FindBoardConfigParam(s.param_id)->name)},
                               {QStringLiteral("values"), values}});
    }
    return out;
}

QVariantMap BoardConfigCatalog::Values(const QString& board_id, const QVariantMap& set) const {
    QVariantMap out;
    for (const cerfcore::DbBoardConfigSetting& s : SettingsFor(board_id)) {
        const QString  id     = QString::fromStdString(s.param_id);
        const QVariant choice = StoredChoice(set, id);
        out.insert(id, Accepts(s, choice) ? choice : NullVariant());
    }
    return out;
}

Json BoardConfigCatalog::Diff(const QString& board_id, const QVariantMap& set, const QVariantMap& base) const {
    const QVariantMap values = Values(board_id, set);
    Json              out    = Json::object();
    for (const cerfcore::DbBoardConfigSetting& s : SettingsFor(board_id)) {
        const QString  id     = QString::fromStdString(s.param_id);
        const QVariant choice = values.value(id);
        const QVariant from   = StoredChoice(base, id);
        if (choice.isNull() == from.isNull() && (choice.isNull() || choice.toString() == from.toString())) continue;
        if (choice.isNull()) out[s.param_id] = nullptr;
        else                 out[s.param_id] = choice.toString().toStdString();
    }
    return out;
}

QString BoardConfigCatalog::ValueLabel(const QString& board_id, const QString& param_id, const QVariant& value) const {
    const cerfcore::DbBoardConfigParam* param =
        emu_.Get<cerfcore::BoardDatabase>().FindBoardConfigParam(param_id.toStdString());
    const auto name = [param](const std::string& id) {
        return QString::fromStdString(cerfcore::FindConfigEnumValue(param->enum_values, id)->name);
    };
    if (value.isNull()) return QStringLiteral("Auto (%1)").arg(name(Setting(board_id, param_id)->default_value));
    return name(value.toString().toStdString());
}

std::vector<std::pair<QString, QString>> BoardConfigCatalog::Rows(const QString& board_id,
                                                                  const QVariantMap& set) const {
    const auto&                              db     = emu_.Get<cerfcore::BoardDatabase>();
    const QVariantMap                        values = Values(board_id, set);
    std::vector<std::pair<QString, QString>> out;
    for (const cerfcore::DbBoardConfigSetting& s : SettingsFor(board_id)) {
        const QString id = QString::fromStdString(s.param_id);
        out.emplace_back(QString::fromStdString(db.FindBoardConfigParam(s.param_id)->name),
                         ValueLabel(board_id, id, values.value(id)));
    }
    return out;
}
