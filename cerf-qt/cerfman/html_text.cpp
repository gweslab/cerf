#include "html_text.h"

#include "../html_link.h"

QString HtmlText::Link(const QString& url, const QString& text) const { return HtmlLink(url, text); }

QString HtmlText::Escaped(const QString& text) const { return text.toHtmlEscaped(); }
