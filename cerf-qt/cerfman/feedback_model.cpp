#include "feedback_model.h"

#include "http_client.h"
#include "json_file.h"

#include "../product_links.h"

#include <QUrl>
#include <QVariantMap>

#include <algorithm>
#include <vector>

REGISTER_SERVICE(FeedbackModel);

namespace {

struct Issue {
    int     number;
    QString title;
    QString url;
    int     reactions;
    int     comments;
};

}

QString FeedbackModel::Header() const {
    return QStringLiteral("The list of issues tracked by the developers. Be patient - some tickets "
                          "might take some time until taken into the work.");
}

QString FeedbackModel::CreateUrl() const { return QString::fromUtf8(cerffrontend::kFeedbackUrl.text); }

QString FeedbackModel::LoadingText() const { return QStringLiteral("Loading issues…"); }

void FeedbackModel::Load() {
    emu_.Get<HttpClient>().Get(
        QUrl(QString::fromLatin1(cerffrontend::kOpenIssuesApiUrl.text)),
        HttpClient::GitHubApiHeaders(), this,
        [this](const QByteArray& body, const QString& error) {
            if (!error.isEmpty()) {
                emit loaded({}, QStringLiteral("Could not reach GitHub.\nGitHub issue API unreachable: %1").arg(error));
                return;
            }
            Parse(body);
        });
}

void FeedbackModel::Parse(const QByteArray& body) {
    QString                   error;
    const std::optional<Json> payload = ParseJsonObject(body, QStringLiteral("GitHub issue API payload"), error);
    if (!payload) {
        emit loaded({}, QStringLiteral("Could not reach GitHub.\n%1").arg(error));
        return;
    }
    const auto items = payload->find("items");
    if (items == payload->end() || !items->is_array()) {
        emit loaded({}, QStringLiteral("Could not reach GitHub.\nGitHub issue API returned no item list"));
        return;
    }
    std::vector<Issue> issues;
    for (const Json& item : *items) {
        if (!item.is_object() || item.contains("pull_request")) continue;
        const std::optional<qint64>  number = JsonInteger(item, "number");
        const std::optional<QString> title  = JsonOptionalText(item, "title");
        const std::optional<QString> url    = JsonNonEmptyText(item, "html_url");
        if (!number || !title || !url) continue;
        const int     id   = int(*number);
        const QString text = title->trimmed();
        issues.push_back(Issue{id, text.isEmpty() ? QStringLiteral("Issue #%1").arg(id) : text, *url,
                               int(JsonInteger(ValueOrNull(item, "reactions"), "total_count").value_or(0)),
                               int(JsonInteger(item, "comments").value_or(0))});
    }
    std::stable_sort(issues.begin(), issues.end(), [](const Issue& a, const Issue& b) {
        if (a.reactions != b.reactions) return a.reactions > b.reactions;
        if (a.comments != b.comments) return a.comments > b.comments;
        return a.number > b.number;
    });
    QVariantList rows;
    for (const Issue& issue : issues)
        rows.append(QVariantMap{{QStringLiteral("label"), QStringLiteral("#%1  %2").arg(issue.number).arg(issue.title)},
                                {QStringLiteral("url"), issue.url},
                                {QStringLiteral("reactions"), issue.reactions}});
    emit loaded(rows, rows.isEmpty() ? QStringLiteral("No open issues.") : QString());
}
