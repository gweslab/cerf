#include "html_link.h"

QString HtmlLink(const QString& url, const QString& text) {
    return QStringLiteral("<a href=\"%1\">%2</a>").arg(url.toHtmlEscaped(), text.toHtmlEscaped());
}
