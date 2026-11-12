#pragma once

#include <QJniEnvironment>
#include <QJniObject>
#include <QString>

inline constexpr char kDocumentsContractClass[] = "android/provider/DocumentsContract";
inline constexpr char kContentResolverClass[]   = "android/content/ContentResolver";

QJniObject AndroidContentResolver();
QJniObject AndroidUri(const QString& text);
QJniObject AndroidDocumentUri(const QJniObject& uri);
QJniObject AndroidTreeDocumentUri(const QJniObject& tree, const QJniObject& document_id);
int        TakePendingJavaErrno(QJniEnvironment& env);
bool       JavaCallSucceeded(QJniEnvironment& env, bool produced);
