#include "file_writer.h"

#include <QDir>

bool FileWriter::Open(QString& error) {
    if (file_.open(QIODevice::WriteOnly | QIODevice::Truncate)) return true;
    error = Failure();
    return false;
}

bool FileWriter::Write(const char* data, qint64 size, QString& error) {
    if (file_.write(data, size) == size) return true;
    error = Failure();
    return false;
}

bool FileWriter::Close(QString& error) {
    file_.close();
    if (file_.error() == QFileDevice::NoError) return true;
    error = Failure();
    return false;
}

QString FileWriter::Failure() const {
    return QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(file_.fileName()), file_.errorString());
}
