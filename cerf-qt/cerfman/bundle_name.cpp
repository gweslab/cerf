#include "bundle_name.h"

#include <QSet>

namespace {

struct NameMark {
    char ch;
    bool may_end;
};

constexpr NameMark kNameMarks[] = {
    {' ', false},
    {'.', false},
    {'-', true},
    {'_', true},
};

bool IsAsciiLetterOrDigit(QChar c) { return c.unicode() < 0x80 && c.isLetterOrNumber(); }

const NameMark* MarkOf(QChar c) {
    for (const NameMark& mark : kNameMarks)
        if (c == QLatin1Char(mark.ch)) return &mark;
    return nullptr;
}

bool IsNameChar(QChar c) { return IsAsciiLetterOrDigit(c) || MarkOf(c) != nullptr; }

bool MayEndName(QChar c) {
    const NameMark* mark = MarkOf(c);
    return mark == nullptr || mark->may_end;
}

bool IsReservedStem(const QString& name) {
    QString stem = name.section(QLatin1Char('.'), 0, 0);
    while (stem.endsWith(QLatin1Char(' '))) stem.chop(1);
    static const QSet<QString> kReserved = [] {
        QSet<QString> names{QStringLiteral("CON"), QStringLiteral("PRN"), QStringLiteral("AUX"), QStringLiteral("NUL")};
        for (int i = 1; i <= 9; ++i) {
            names.insert(QStringLiteral("COM%1").arg(i));
            names.insert(QStringLiteral("LPT%1").arg(i));
        }
        return names;
    }();
    return kReserved.contains(stem.toUpper());
}

}

bool IsSafeBundleName(const QString& name) {
    if (name.isEmpty() || !IsAsciiLetterOrDigit(name.front()) || !MayEndName(name.back())) return false;
    for (const QChar c : name)
        if (!IsNameChar(c)) return false;
    return !IsReservedStem(name);
}

QString SafeBundleNameFrom(const QString& text) {
    QString name;
    for (const QChar c : text) name.append(IsNameChar(c) ? c : QLatin1Char(' '));
    name = name.simplified();
    while (!name.isEmpty() && !IsAsciiLetterOrDigit(name.front())) name.remove(0, 1);
    while (!name.isEmpty() && !MayEndName(name.back())) name.chop(1);
    return IsSafeBundleName(name) ? name : QString();
}

QString BundleNameRule() {
    return QStringLiteral("Use letters, digits, spaces, dots, dashes, or underscores; it must start with a letter or "
                          "digit and must not end with a space or dot.");
}
