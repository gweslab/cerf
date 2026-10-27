#include "about_model.h"

#include "desktop_shell.h"
#include "../svg_document.h"

#include "../html_link.h"
#include "../install_root_files.h"
#include "../product_links.h"
#include "../qt_resource_paths.h"
#include "../resource_paths_text.h"
#include "../version.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>

#include <QDate>
#include <QResource>
#include <QStringList>

#include <utility>

REGISTER_SERVICE(AboutModel);

QString AboutModel::Version() const { return QStringLiteral(CERF_VERSION_STR); }

QString AboutModel::VersionLabel() const { return QStringLiteral(CERF_VERSION_LABEL); }

QString AboutModel::Build() const { return QString::fromUtf8(CERF_VERSION_BUILD_STR); }

QString AboutModel::LinksHtml() const {
    QStringList links;
    const std::pair<const char*, const char*> entries[] = {
        {"Website", cerffrontend::kWebsiteUrl},
        {"Discord", cerffrontend::kDiscordUrl},
        {"Patreon", cerffrontend::kPatreonUrl},
    };
    for (const auto& [label, url] : entries)
        links.append(HtmlLink(QString::fromUtf8(url), QString::fromUtf8(label)));
    return links.join(QStringLiteral("&nbsp;&nbsp;·&nbsp;&nbsp;"));
}

QString AboutModel::ContributorsHeader() const {
    return QStringLiteral("Thanks to project contributors:");
}

QString AboutModel::Contributors() const {
    QStringList names;
    for (const QString& line :
         QString::fromUtf8(QResource(ContributorsResource()).uncompressedData()).split(QLatin1Char('\n')))
        if (!line.trimmed().isEmpty()) names.append(line.trimmed());
    names.append(QStringLiteral("everyone else who helped"));
    return names.join(Separator());
}

QString AboutModel::Separator() const { return QStringLiteral("   •   "); }

QString AboutModel::Copyright() const {
    const int year  = QDate::currentDate().year();
    const int first = cerffrontend::kProductFirstYear;
    const QString years =
        year <= first ? QString::number(first) : QStringLiteral("%1-%2").arg(first).arg(year);
    return QStringLiteral("Copyright © %1 ").arg(years);
}

QString AboutModel::Author() const { return QString::fromUtf8(cerffrontend::kProductAuthor); }

QString AboutModel::AuthorUrl() const { return QString::fromUtf8(cerffrontend::kProductAuthorUrl); }

QString AboutModel::LicensesTitle() const { return QStringLiteral("Licenses"); }

qreal AboutModel::BandAspect() const {
    const QSizeF size = SvgDocument(AssetIconResource(QStringLiteral(CERF_ABOUT_BAND_ASSET))).DefaultSize();
    return size.height() / size.width();
}

QString AboutModel::OpenLicenses() const {
    return emu_.Get<DesktopShell>().OpenPath(QString::fromStdString(cerfcore::GetCerfDir()) +
                                             QString::fromUtf8(cerffrontend::kNoticesFileName));
}
