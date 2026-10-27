#pragma once

#include <QColor>
#include <QObject>
#include <QString>
#include <QtQml/qqmlregistration.h>

class IconSources : public QObject {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(QString aboutBand READ AboutBand CONSTANT)
    Q_PROPERTY(QString errorImage READ ErrorImage CONSTANT)
    Q_PROPERTY(QString newIcon READ NewIcon CONSTANT)
    Q_PROPERTY(QString settingsIcon READ SettingsIcon CONSTANT)
    Q_PROPERTY(QString launchSymbol READ LaunchSymbol CONSTANT)
    Q_PROPERTY(QString resumeSymbol READ ResumeSymbol CONSTANT)
    Q_PROPERTY(QString launchIcon READ LaunchIcon CONSTANT)

public:
    using QObject::QObject;

    QString AboutBand() const;
    QString ErrorImage() const;
    QString NewIcon() const;
    QString SettingsIcon() const;
    QString LaunchSymbol() const;
    QString ResumeSymbol() const;
    QString LaunchIcon() const;

    Q_INVOKABLE QString Icon(const QString& name) const;
    Q_INVOKABLE QString Asset(const QString& stem) const;
    Q_INVOKABLE QString Tinted(const QString& name, const QColor& color) const;
};
