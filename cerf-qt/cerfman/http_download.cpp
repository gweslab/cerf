#include "http_download.h"

#include "file_writer.h"
#include "filesystem_path.h"
#include "http_client.h"
#include "sha256_text.h"

#include <QCryptographicHash>
#include <QEventLoop>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>
#include <QUrl>

namespace {

constexpr int kTransferTimeoutMs = 120000;
constexpr int kCancelPollMs      = 100;

}

OperationResult DownloadVerified(const DownloadRequest& request, const OperationProgress& progress, QString& error) {
    FileWriter file(request.destination);
    if (!file.Open(error)) return OperationResult::kFailed;

    QNetworkAccessManager manager;
    QNetworkReply* reply = manager.get(HttpClient::Request(QUrl(request.url), request.user_agent, kTransferTimeoutMs));
    QCryptographicHash hash(QCryptographicHash::Sha256);
    QEventLoop         loop;
    QTimer             cancel_poll;
    qint64             done      = 0;
    std::optional<qint64> total  = request.expected_size;
    bool               cancelled = false;
    QString            failure;

    const QString progress_label = QStringLiteral("Downloading %1…").arg(request.label);
    progress.Report(progress_label, 0, total);
    QObject::connect(reply, &QNetworkReply::metaDataChanged, &loop, [&] {
        const QVariant length = reply->header(QNetworkRequest::ContentLengthHeader);
        if (length.isValid()) total = length.toLongLong();
    });
    QObject::connect(reply, &QNetworkReply::readyRead, &loop, [&] {
        while (reply->bytesAvailable() > 0) {
            const QByteArray chunk = reply->read(FileWriter::kChunkBytes);
            if (!file.Write(chunk, failure)) {
                reply->abort();
                return;
            }
            hash.addData(chunk);
            done += chunk.size();
        }
        progress.Report(progress_label, done, total);
    });
    QObject::connect(&cancel_poll, &QTimer::timeout, &loop, [&] {
        if (!progress.Cancelled()) return;
        cancelled = true;
        reply->abort();
    });
    QObject::connect(reply, &QNetworkReply::finished, &loop, &QEventLoop::quit);
    cancel_poll.start(kCancelPollMs);
    loop.exec();
    cancel_poll.stop();

    const bool network_ok = reply->error() == QNetworkReply::NoError;
    if (network_ok) {
        const QByteArray rest = reply->readAll();
        if (!rest.isEmpty()) {
            file.Write(rest, failure);
            hash.addData(rest);
            done += rest.size();
        }
    }
    const QString network_error = reply->errorString();
    delete reply;
    QString closing;
    if (!file.Close(closing) && failure.isEmpty()) failure = closing;

    const auto drop = [&](OperationResult result) {
        QString cleanup;
        if (!RemoveEntry(PathOf(request.destination), cleanup)) error += QLatin1Char('\n') + cleanup;
        return result;
    };
    if (cancelled) {
        error = QStringLiteral("%1: cancelled").arg(request.label);
        return drop(OperationResult::kCancelled);
    }
    if (!failure.isEmpty()) {
        error = failure;
        return drop(OperationResult::kFailed);
    }
    if (!network_ok) {
        error = QStringLiteral("%1: %2").arg(request.label, network_error);
        return drop(OperationResult::kFailed);
    }
    if (request.expected_size && done != *request.expected_size) {
        error = QStringLiteral("%1: size mismatch (got %2, expected %3)")
                    .arg(request.label)
                    .arg(done)
                    .arg(*request.expected_size);
        return drop(OperationResult::kFailed);
    }
    if (request.expected_sha256) {
        const QString digest = QString::fromLatin1(hash.result().toHex());
        if (!SameSha256(digest, *request.expected_sha256)) {
            error = QStringLiteral("%1: sha256 mismatch (got %2, expected %3)")
                        .arg(request.label, digest, *request.expected_sha256);
            return drop(OperationResult::kFailed);
        }
    }
    return OperationResult::kDone;
}
