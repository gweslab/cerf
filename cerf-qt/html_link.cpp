#include "html_link.h"

#include "link_target.h"

QString HtmlLink(const QString& url, const QString& text) {
    const QString target = LinkTarget(url);
    if (target.isEmpty()) return text.toHtmlEscaped();
    return QStringLiteral("<a href=\"%1\">%2</a>").arg(target.toHtmlEscaped(), text.toHtmlEscaped());
}
