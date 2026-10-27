#include "json_file.h"

#include "host_error_text.h"
#include "whole_number.h"

#include <cerfcore/core/config_json.h>

#include <QByteArray>
#include <QDir>
#include <QVariantList>
#include <QVariantMap>

#include <cmath>
#include <limits>

namespace {

std::optional<Json> ReadObject(const QString& path, bool absent_is_empty, QString& error) {
    std::string                  text;
    const cerfcore::HostFileRead read = cerfcore::CfgReadTextFile(path.toStdString(), text);
    if (read == cerfcore::HostFileRead::kAbsent && absent_is_empty) return Json::object();
    if (read != cerfcore::HostFileRead::kRead) {
        error = (read == cerfcore::HostFileRead::kAbsent ? QStringLiteral("%1 does not exist.")
                                                          : QStringLiteral("%1 cannot be read."))
                    .arg(QDir::toNativeSeparators(path));
        return std::nullopt;
    }
    return ParseJsonObject(QByteArray::fromStdString(text), path, error);
}

}

Json LoadJsonObject(const QString& path) {
    QString error;
    return ReadJsonObject(path, error).value_or(Json::object());
}

std::optional<Json> ReadJsonObject(const QString& path, QString& error) { return ReadObject(path, false, error); }

std::optional<Json> ReadJsonObjectIfPresent(const QString& path, QString& error) {
    return ReadObject(path, true, error);
}

std::optional<Json> ParseJsonObject(const QByteArray& bytes, const QString& source, QString& error) {
    std::string         message;
    std::optional<Json> parsed = cerfcore::CfgParseJsonObject<Json>(
        std::string_view(bytes.constData(), static_cast<size_t>(bytes.size())), message);
    if (!parsed) error = QStringLiteral("%1 %2.").arg(source, QString::fromStdString(message));
    return parsed;
}

bool WriteJsonFile(const QString& path, const Json& value, QString& error) {
    uint32_t code = 0;
    if (cerfcore::CfgWriteJsonFile(path.toStdString(), value, code)) return true;
    error = QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(path), HostErrorText(code));
    return false;
}

Json FillMissingKeys(const Json& target, const Json& source) {
    if (!target.is_object() || !source.is_object()) return target;
    Json out = target;
    for (const auto& [key, value] : source.items()) {
        const auto it = out.find(key);
        if (it != out.end()) *it = FillMissingKeys(*it, value);
        else                 out[key] = value;
    }
    return out;
}

Json ValueOrNull(const Json& object, const char* key) {
    const auto it = object.find(key);
    return it != object.end() ? *it : Json(nullptr);
}

QString JsonString(const Json& value) { return QString::fromStdString(value.get<std::string>()); }

std::optional<QString> JsonPresentText(const Json& object, const char* key) {
    const auto it = object.find(key);
    if (it == object.end()) return std::nullopt;
    return JsonString(*it);
}

std::optional<QString> JsonOptionalText(const Json& object, const char* key) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_string()) return std::nullopt;
    return JsonString(*it);
}

std::optional<QString> NonEmptyText(const QString& text) {
    if (text.isEmpty()) return std::nullopt;
    return text;
}

std::optional<QString> JsonNonEmptyText(const Json& object, const char* key) {
    const std::optional<QString> text = JsonOptionalText(object, key);
    return text ? NonEmptyText(*text) : std::nullopt;
}

QString JsonText(const Json& object, const char* key) { return JsonOptionalText(object, key).value_or(QString()); }

std::optional<qint64> JsonInteger(const Json& object, const char* key) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_number_integer()) return std::nullopt;
    return it->get<qint64>();
}

std::optional<bool> JsonBool(const Json& object, const char* key) {
    const auto it = object.find(key);
    if (it == object.end() || !it->is_boolean()) return std::nullopt;
    return it->get<bool>();
}

QVariant NullVariant() { return QVariant::fromMetaType(QMetaType::fromType<std::nullptr_t>()); }

QVariant JsonToVariant(const Json& value) {
    switch (value.type()) {
        case Json::value_t::object: {
            QVariantMap map;
            for (const auto& [key, item] : value.items())
                map.insert(QString::fromStdString(key), JsonToVariant(item));
            return map;
        }
        case Json::value_t::array: {
            QVariantList list;
            for (const auto& item : value) list.append(JsonToVariant(item));
            return list;
        }
        case Json::value_t::string:
            return JsonString(value);
        case Json::value_t::boolean:
            return value.get<bool>();
        case Json::value_t::number_integer:
            return QVariant::fromValue(value.get<qint64>());
        case Json::value_t::number_unsigned:
            return QVariant::fromValue(value.get<quint64>());
        case Json::value_t::number_float:
            return value.get<double>();
        case Json::value_t::null:
            return NullVariant();
        default:
            return QVariant();
    }
}

Json VariantToJson(const QVariant& value) {
    switch (value.typeId()) {
        case QMetaType::QVariantMap: {
            Json        out  = Json::object();
            const auto  map  = value.toMap();
            for (auto it = map.constBegin(); it != map.constEnd(); ++it)
                out[it.key().toStdString()] = VariantToJson(it.value());
            return out;
        }
        case QMetaType::QVariantList:
        case QMetaType::QStringList: {
            Json out = Json::array();
            for (const QVariant& item : value.toList()) out.push_back(VariantToJson(item));
            return out;
        }
        case QMetaType::QString:
            return value.toString().toStdString();
        case QMetaType::Bool:
            return value.toBool();
        case QMetaType::Int:
        case QMetaType::LongLong:
            return value.toLongLong();
        case QMetaType::UInt:
        case QMetaType::ULongLong:
            return value.toULongLong();
        case QMetaType::Double:
        case QMetaType::Float: {
            const double number = value.toDouble();
            if (IsWholeNumber(number) &&
                std::fabs(number) < static_cast<double>(std::numeric_limits<qint64>::max()))
                return static_cast<qint64>(number);
            return number;
        }
        default:
            return nullptr;
    }
}
