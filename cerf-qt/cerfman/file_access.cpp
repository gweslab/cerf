#include "file_access.h"

#include "device_file_value.h"
#include "filesystem_path.h"
#include "picked_document.h"

#include <QDir>
#include <QFileInfo>

REGISTER_SERVICE(FileAccess);

QString FileAccess::LocalPath(const QUrl& url) const {
    if (url.isLocalFile()) return QDir::toNativeSeparators(url.toLocalFile());
    return AdoptPickedDocument(url);
}

QUrl FileAccess::FileUrl(const QString& value, const QString& base_dir) const {
    const QString path = ResolveDeviceFileValue(value, base_dir);
    if (path.isEmpty()) return QUrl();
    if (IsDocumentFileValue(path)) return QUrl(path);
    return QUrl::fromLocalFile(QFileInfo(path).absoluteFilePath());
}

QUrl FileAccess::BrowseFolder(const QString& value, const QString& base_dir) const {
    const QString path = ResolveDeviceFileValue(value, base_dir);
    if (!path.isEmpty() && !IsDocumentFileValue(path)) {
        const QString folder = QFileInfo(path).absolutePath();
        if (QFileInfo(folder).isDir()) return QUrl::fromLocalFile(folder);
    }
    if (!base_dir.isEmpty() && QFileInfo(base_dir).isDir())
        return QUrl::fromLocalFile(QFileInfo(base_dir).absoluteFilePath());
    return QUrl();
}

QString FileAccess::PickedValue(const QString& path, const QString& base_dir) const {
    if (IsDocumentFileValue(path)) return path;
    const QFileInfo picked(QDir::fromNativeSeparators(path));
    if (!base_dir.isEmpty() &&
        QDir::cleanPath(picked.absolutePath()) == QDir::cleanPath(QFileInfo(base_dir).absoluteFilePath()))
        return picked.fileName();
    return QDir::toNativeSeparators(picked.absoluteFilePath());
}

QString FileAccess::DisplayText(const QString& value) const { return LocationName(value); }
