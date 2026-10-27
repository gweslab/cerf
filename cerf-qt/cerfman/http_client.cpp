#include "http_client.h"

#include <cerfcore/core/cerf_emulator.h>
#include "../product_links.h"
#include "../version.h"

#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>

REGISTER_SERVICE(HttpClient);

HttpClient::~HttpClient() = default;

void HttpClient::OnShutdown() { manager_.reset(); }

QNetworkAccessManager& HttpClient::Manager() {
    if (!manager_) manager_ = std::make_unique<QNetworkAccessManager>();
    return *manager_;
}

QByteArray HttpClient::UserAgent() const { return QByteArrayLiteral("CERF/" CERF_VERSION_STR); }

HttpClient::Headers HttpClient::GitHubApiHeaders() {
    return {qMakePair(QByteArrayLiteral("Accept"), QByteArray(cerffrontend::kGitHubApiMediaType))};
}

QNetworkRequest HttpClient::Request(const QUrl& url, const QByteArray& user_agent, int timeout_ms) {
    QNetworkRequest request(url);
    request.setHeader(QNetworkRequest::UserAgentHeader, user_agent);
    request.setTransferTimeout(timeout_ms);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::NoLessSafeRedirectPolicy);
    return request;
}

void HttpClient::Get(const QUrl& url, const Headers& headers, QObject* context, Done done,
                     int timeout_ms) {
    QNetworkRequest request = Request(url, UserAgent(), timeout_ms);
    for (const auto& [name, value] : headers) request.setRawHeader(name, value);
    QNetworkReply* reply = Manager().get(request);
    QObject::connect(reply, &QNetworkReply::finished, context, [reply, done = std::move(done)] {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            done(QByteArray(), reply->errorString());
            return;
        }
        done(reply->readAll(), QString());
    });
}
