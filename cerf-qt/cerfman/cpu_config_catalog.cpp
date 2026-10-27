#include "cpu_config_catalog.h"

#include "board_catalog.h"
#include "json_file.h"

#include <cerfcore/core/board_database.h>
#include <cerfcore/core/cerf_emulator.h>

#include <charconv>
#include <string>
#include <system_error>

REGISTER_SERVICE(CpuConfigCatalog);

namespace {

using cerfcore::CpuConfigParam;
using cerfcore::CpuConfigParamType;
using cerfcore::CpuConfigPreset;

QString HexText(quint64 value) {
    return QStringLiteral("0x") + QStringLiteral("%1").arg(value, 8, 16, QLatin1Char('0')).toUpper();
}

QVariantList Options(const CpuConfigParam& param) {
    if (param.type == CpuConfigParamType::Boolean) return {NullVariant(), true, false};
    QVariantList out;
    if (param.type == CpuConfigParamType::Enum) {
        out.append(NullVariant());
        for (const auto& e : param.enum_values) out.append(QString::fromStdString(e.id));
    }
    return out;
}

QString ParamLabel(const CpuConfigParam& param) { return QString::fromStdString(param.name); }

QVariant Normalized(const CpuConfigParam& param, const QVariant& value) {
    uint32_t number = 0;
    if (param.type == CpuConfigParamType::Hex && value.typeId() == QMetaType::QString &&
        cerfcore::ParseCpuConfigHex(value.toString().toStdString(), number))
        return QVariant::fromValue(number);
    return value;
}

}

const CpuConfigParam* CpuConfigCatalog::Param(const QString& param_id) const {
    return emu_.Get<cerfcore::CpuConfigDatabase>().FindParam(param_id.toStdString());
}

std::vector<const CpuConfigParam*> CpuConfigCatalog::ParamsFor(const QString& board_id) const {
    std::vector<const CpuConfigParam*>   out;
    const std::optional<cerfcore::CpuArch> arch = emu_.Get<BoardCatalog>().Arch(board_id);
    if (!arch) return out;
    for (const auto& param : emu_.Get<cerfcore::CpuConfigDatabase>().Params())
        if (param.arch == *arch) out.push_back(&param);
    return out;
}

std::vector<const CpuConfigPreset*> CpuConfigCatalog::PresetsFor(const QString& board_id) const {
    std::vector<const CpuConfigPreset*>  out;
    const std::optional<cerfcore::CpuArch> arch = emu_.Get<BoardCatalog>().Arch(board_id);
    if (!arch) return out;
    auto& db = emu_.Get<cerfcore::BoardDatabase>();
    for (const auto& preset : emu_.Get<cerfcore::CpuConfigDatabase>().Presets())
        if (!preset.soc_id.empty() && db.SocArch(preset.soc_id) == *arch) out.push_back(&preset);
    return out;
}

QVariant CpuConfigCatalog::ToVariant(const CpuConfigParam& param,
                                     const cerfcore::CpuConfigValue& value) const {
    switch (param.type) {
        case CpuConfigParamType::Boolean: return value.boolean;
        case CpuConfigParamType::Integer: return QVariant::fromValue(static_cast<qint64>(value.number));
        case CpuConfigParamType::Hex:     return HexText(value.number);
        case CpuConfigParamType::Enum:    return QString::fromStdString(value.enum_id);
    }
    return QVariant();
}

QVariantMap CpuConfigCatalog::ValuesOf(const QString& board_id,
                                       const cerfcore::CpuConfigValues& values) const {
    QVariantMap out;
    for (const CpuConfigParam* param : ParamsFor(board_id)) {
        const auto it = values.find(param->id);
        if (it != values.end()) out.insert(QString::fromStdString(param->id), ToVariant(*param, it->second));
    }
    return out;
}

QVariantMap CpuConfigCatalog::Defaults(const QString& board_id) const {
    const cerfcore::DbBoard* board = emu_.Get<BoardCatalog>().Find(board_id);
    if (!board) return {};
    return ValuesOf(board_id, emu_.Get<cerfcore::CpuConfigDatabase>().ResolvePreset(board->soc_id));
}

QVariantList CpuConfigCatalog::Params(const QString& board_id) const {
    const QVariantMap defaults = Defaults(board_id);
    QVariantList      out;
    for (const CpuConfigParam* param : ParamsFor(board_id)) {
        const QString id = QString::fromStdString(param->id);
        out.append(QVariantMap{{QStringLiteral("id"), id},
                               {QStringLiteral("name"), ParamLabel(*param)},
                               {QStringLiteral("options"), Options(*param)},
                               {QStringLiteral("default"), defaults.value(id)}});
    }
    return out;
}

QVariantList CpuConfigCatalog::PresetChoices(const QString& board_id) const {
    QVariantList out{NullVariant()};
    const int    count = static_cast<int>(PresetsFor(board_id).size());
    for (int index = 0; index < count; ++index) out.append(index);
    return out;
}

QString CpuConfigCatalog::AutoPresetLabel(const QString& board_id) const {
    const cerfcore::DbBoard* board = emu_.Get<BoardCatalog>().Find(board_id);
    if (!board) return QString();
    return QStringLiteral("Auto (%1)")
        .arg(QString::fromStdString(emu_.Get<cerfcore::BoardDatabase>().Soc(board->soc_id).name));
}

QString CpuConfigCatalog::PresetChoiceLabel(const QString& board_id, const QVariant& choice) const {
    if (choice.isNull()) return AutoPresetLabel(board_id);
    const int  index = choice.toInt();
    const auto list  = PresetsFor(board_id);
    if (index < 0) return QStringLiteral("Custom");
    return QString::fromStdString(emu_.Get<cerfcore::BoardDatabase>().Soc(list[size_t(index)]->soc_id).name);
}

QVariant CpuConfigCatalog::CurrentPreset(const QString& board_id, const QVariantMap& overrides) const {
    if (overrides.isEmpty()) return NullVariant();
    return MatchingPreset(board_id, overrides);
}

QString CpuConfigCatalog::PresetLabel(const QString& board_id, const QVariantMap& overrides) const {
    return PresetChoiceLabel(board_id, CurrentPreset(board_id, overrides));
}

QVariantMap CpuConfigCatalog::PresetValues(const QString& board_id, int index) const {
    return ValuesOf(board_id, emu_.Get<cerfcore::CpuConfigDatabase>().Resolve(
                                  *PresetsFor(board_id)[static_cast<size_t>(index)]));
}

int CpuConfigCatalog::MatchingPreset(const QString& board_id, const QVariantMap& overrides) const {
    QVariantMap values = Defaults(board_id);
    for (auto it = overrides.constBegin(); it != overrides.constEnd(); ++it) values.insert(it.key(), it.value());
    const auto params = ParamsFor(board_id);
    const int  count  = static_cast<int>(PresetsFor(board_id).size());
    for (int index = 0; index < count; ++index) {
        const QVariantMap resolved = PresetValues(board_id, index);
        bool              match    = true;
        for (const CpuConfigParam* p : params) {
            const QString id = QString::fromStdString(p->id);
            if (Normalized(*p, resolved.value(id)) != Normalized(*p, values.value(id))) {
                match = false;
                break;
            }
        }
        if (match) return index;
    }
    return -1;
}

std::vector<std::pair<QString, QString>> CpuConfigCatalog::OverrideRows(const QString& board_id,
                                                                    const QVariantMap& overrides) const {
    std::vector<std::pair<QString, QString>> out;
    for (const CpuConfigParam* param : ParamsFor(board_id)) {
        const QString id = QString::fromStdString(param->id);
        if (overrides.contains(id)) out.emplace_back(ParamLabel(*param), ValueLabel(id, overrides.value(id)));
    }
    return out;
}

QString CpuConfigCatalog::ValueLabel(const QString& param_id, const QVariant& value) const {
    const CpuConfigParam* param = Param(param_id);
    switch (param->type) {
        case CpuConfigParamType::Boolean:
            return value.toBool() ? QStringLiteral("Enabled") : QStringLiteral("Disabled");
        case CpuConfigParamType::Enum:
            for (const auto& e : param->enum_values)
                if (QString::fromStdString(e.id) == value.toString()) return QString::fromStdString(e.name);
            return value.toString();
        case CpuConfigParamType::Hex: {
            const QVariant number = Normalized(*param, value);
            if (number.typeId() == QMetaType::UInt) return HexText(number.toUInt());
            return value.toString();
        }
        case CpuConfigParamType::Integer:
            return value.toString();
    }
    return value.toString();
}

QString CpuConfigCatalog::ParamValueLabel(const QString& param_id, const QVariant& default_value,
                                          const QVariant& override_value) const {
    if (!override_value.isValid() || override_value.isNull())
        return QStringLiteral("Auto (%1)").arg(ValueLabel(param_id, default_value));
    return ValueLabel(param_id, override_value);
}

QVariant CpuConfigCatalog::ParseText(const QString& param_id, const QString& raw) const {
    const CpuConfigParam* param = Param(param_id);
    const QString text = raw.trimmed();
    const std::string utf8   = text.toStdString();
    uint32_t          number = 0;
    if (param->type == CpuConfigParamType::Hex) {
        if (!cerfcore::ParseCpuConfigHex(utf8, number)) return QVariant();
        return HexText(number);
    }
    if (param->type == CpuConfigParamType::Integer) {
        const char* const end    = utf8.data() + utf8.size();
        const auto        parsed = std::from_chars(utf8.data(), end, number);
        if (utf8.empty() || parsed.ec != std::errc() || parsed.ptr != end) return QVariant();
        return QVariant::fromValue(static_cast<qint64>(number));
    }
    return QVariant();
}

QString CpuConfigCatalog::InvalidMessage(const QString& param_id) const {
    const CpuConfigParam* param = Param(param_id);
    const QString         name  = ParamLabel(*param);
    if (param->type == CpuConfigParamType::Hex)
        return QStringLiteral("Enter a hexadecimal value such as 0x1F for %1.").arg(name);
    return QStringLiteral("Enter a whole number for %1.").arg(name);
}
