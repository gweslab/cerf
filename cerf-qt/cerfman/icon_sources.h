#pragma once

#include <QColor>
#include <QObject>
#include <QPointF>
#include <QString>
#include <QtQml/qqmlregistration.h>

class IconSources : public QObject {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(QString aboutBand READ AboutBand CONSTANT)
    Q_PROPERTY(QString logo READ Logo CONSTANT)
    Q_PROPERTY(QString newIcon READ NewIcon CONSTANT)
    Q_PROPERTY(QString settingsIcon READ SettingsIcon CONSTANT)
    Q_PROPERTY(QString launchSymbol READ LaunchSymbol CONSTANT)
    Q_PROPERTY(QString resumeSymbol READ ResumeSymbol CONSTANT)
    Q_PROPERTY(QString launchIcon READ LaunchIcon CONSTANT)
    Q_PROPERTY(QString cursorSymbol READ CursorSymbol CONSTANT)
    Q_PROPERTY(QPointF cursorHotspot READ CursorHotspot CONSTANT)

public:
    using QObject::QObject;

    QString AboutBand() const;
    QString Logo() const;
    QString NewIcon() const;
    QString SettingsIcon() const;
    QString LaunchSymbol() const;
    QString ResumeSymbol() const;
    QString LaunchIcon() const;
    QString CursorSymbol() const;
    QPointF CursorHotspot() const;

    Q_INVOKABLE QString Icon(const QString& name) const;
    Q_INVOKABLE QString Asset(const QString& stem) const;
    Q_INVOKABLE QString Tinted(const QString& name, const QColor& color) const;
};
