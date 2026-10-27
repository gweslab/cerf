#pragma once

#include <QString>
#include <QStringList>

QString SortText(const QString& text);
bool    SortTextLess(const QString& a, const QString& b);
bool    MatchesQuery(const QStringList& fields, const QString& query);
