#pragma once

#include <QString>
#include <QUrl>

QString AdoptPickedDocument(const QUrl& url);
bool    DeletePickedDocument(const QString& uri);
