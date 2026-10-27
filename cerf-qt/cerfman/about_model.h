#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QtQml/qqmlregistration.h>

class AboutModel : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(QString version READ Version CONSTANT)
    Q_PROPERTY(QString versionLabel READ VersionLabel CONSTANT)
    Q_PROPERTY(QString build READ Build CONSTANT)
    Q_PROPERTY(QString linksHtml READ LinksHtml CONSTANT)
    Q_PROPERTY(QString contributorsHeader READ ContributorsHeader CONSTANT)
    Q_PROPERTY(QString contributors READ Contributors CONSTANT)
    Q_PROPERTY(QString separator READ Separator CONSTANT)
    Q_PROPERTY(QString copyright READ Copyright CONSTANT)
    Q_PROPERTY(QString author READ Author CONSTANT)
    Q_PROPERTY(QString authorUrl READ AuthorUrl CONSTANT)
    Q_PROPERTY(QString licensesTitle READ LicensesTitle CONSTANT)
    Q_PROPERTY(qreal bandAspect READ BandAspect CONSTANT)

public:
    explicit AboutModel(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static AboutModel* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<AboutModel>(qml);
    }

    QString      Version() const;
    QString      VersionLabel() const;
    QString      Build() const;
    QString      LinksHtml() const;
    QString      ContributorsHeader() const;
    QString      Contributors() const;
    QString      Separator() const;
    QString      Copyright() const;
    QString      Author() const;
    QString      AuthorUrl() const;
    QString      LicensesTitle() const;
    qreal        BandAspect() const;

    Q_INVOKABLE QString OpenLicenses() const;
};
