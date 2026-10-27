#include "text_compare.h"

#include <algorithm>

QString SortText(const QString& text) { return text.toCaseFolded().simplified(); }

bool SortTextLess(const QString& a, const QString& b) { return SortText(a) < SortText(b); }

bool MatchesQuery(const QStringList& fields, const QString& query) {
    const QString needle = query.trimmed().toCaseFolded();
    return needle.isEmpty() || std::any_of(fields.begin(), fields.end(), [&needle](const QString& field) {
               return field.toCaseFolded().contains(needle);
           });
}
