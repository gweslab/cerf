#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

class SourceRepositories : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(QString title READ Title CONSTANT)
    Q_PROPERTY(QString addTitle READ AddTitle CONSTANT)
    Q_PROPERTY(QString addPrompt READ AddPrompt CONSTANT)
    Q_PROPERTY(QString checking READ Checking CONSTANT)

public:
    explicit SourceRepositories(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static SourceRepositories* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<SourceRepositories>(qml);
    }

    QString Title() const { return QStringLiteral("Bundle repositories"); }
    QString AddTitle() const { return QStringLiteral("Add bundle repository"); }
    QString AddPrompt() const { return QStringLiteral("Bundle repository URL:"); }
    QString Checking() const;

    Q_INVOKABLE QVariantList List() const;
    Q_INVOKABLE void         Probe(const QString& url);
    Q_INVOKABLE QVariantMap  Check(const QString& url, const QStringList& existing) const;
    Q_INVOKABLE QString      Apply(const QVariantList& repositories);

signals:
    void probed(const QString& url, const QString& status);
};
