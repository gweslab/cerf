#pragma once

#include <QByteArray>
#include <QFile>
#include <QString>

class FileWriter {
public:
    static constexpr qint64 kChunkBytes = 1024 * 1024;

    explicit FileWriter(const QString& path) : file_(path) {}

    bool Open(QString& error);
    bool Write(const char* data, qint64 size, QString& error);
    bool Write(const QByteArray& data, QString& error) { return Write(data.constData(), data.size(), error); }
    bool Close(QString& error);

private:
    QString Failure() const;

    QFile file_;
};
