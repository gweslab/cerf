#pragma once

#include <cerfcore/core/service.h>

#include <QByteArray>
#include <QList>
#include <QPair>
#include <QString>
#include <QUrl>

#include <functional>
#include <memory>

class QNetworkAccessManager;
class QNetworkRequest;
class QObject;

class HttpClient : public cerfcore::Service {
public:
    using Headers = QList<QPair<QByteArray, QByteArray>>;
    using Done    = std::function<void(const QByteArray& body, const QString& error)>;

    static constexpr int kDefaultTimeoutMs = 30000;

    using cerfcore::Service::Service;
    ~HttpClient() override;

    void OnShutdown() override;

    void Get(const QUrl& url, const Headers& headers, QObject* context, Done done,
             int timeout_ms = kDefaultTimeoutMs);

    QByteArray UserAgent() const;

    static QNetworkRequest Request(const QUrl& url, const QByteArray& user_agent, int timeout_ms);
    static Headers         GitHubApiHeaders();

private:
    QNetworkAccessManager& Manager();

    std::unique_ptr<QNetworkAccessManager> manager_;
};
