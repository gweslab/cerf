#include "qt_menu_item_text.h"

QString MenuItemText(const std::string& label) {
    const QString text = QString::fromStdString(label);
    const qsizetype tab = text.indexOf(QLatin1Char('\t'));
    if (tab < 0) return text;
    return text.left(tab) + QLatin1String(" (") + text.mid(tab + 1) + QLatin1Char(')');
}
