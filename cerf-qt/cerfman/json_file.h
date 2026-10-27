#pragma once

#include <nlohmann/json.hpp>

#include <QByteArray>
#include <QString>
#include <QVariant>

#include <optional>

using Json = nlohmann::ordered_json;

Json                LoadJsonObject(const QString& path);
std::optional<Json> ReadJsonObject(const QString& path, QString& error);
std::optional<Json> ReadJsonObjectIfPresent(const QString& path, QString& error);
std::optional<Json> ParseJsonObject(const QByteArray& bytes, const QString& source, QString& error);
bool WriteJsonFile(const QString& path, const Json& value, QString& error);
Json FillMissingKeys(const Json& target, const Json& source);

Json                   ValueOrNull(const Json& object, const char* key);
QString                JsonString(const Json& value);
std::optional<QString> JsonPresentText(const Json& object, const char* key);
std::optional<QString> JsonOptionalText(const Json& object, const char* key);
std::optional<QString> NonEmptyText(const QString& text);
std::optional<QString> JsonNonEmptyText(const Json& object, const char* key);
QString                JsonText(const Json& object, const char* key);
std::optional<qint64>  JsonInteger(const Json& object, const char* key);
std::optional<bool>    JsonBool(const Json& object, const char* key);

QVariant NullVariant();
QVariant JsonToVariant(const Json& value);
Json     VariantToJson(const QVariant& value);
