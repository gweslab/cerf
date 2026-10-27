#pragma once

#include <QObject>
#include <QString>
#include <QtQml/qqmlregistration.h>

class SheetIds : public QObject {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(QString boardId READ BoardId CONSTANT)
    Q_PROPERTY(QString name READ Name CONSTANT)
    Q_PROPERTY(QString rom READ Rom CONSTANT)
    Q_PROPERTY(QString storage READ Storage CONSTANT)
    Q_PROPERTY(QString guestAdditions READ GuestAdditions CONSTANT)
    Q_PROPERTY(QString networkEnabled READ NetworkEnabled CONSTANT)
    Q_PROPERTY(QString colorScheme READ ColorScheme CONSTANT)
    Q_PROPERTY(QString fullScreen READ FullScreen CONSTANT)
    Q_PROPERTY(QString dpi READ Dpi CONSTANT)
    Q_PROPERTY(QString fontSize READ FontSize CONSTANT)
    Q_PROPERTY(QString clearType READ ClearType CONSTANT)
    Q_PROPERTY(QString allowUntrustedApps READ AllowUntrustedApps CONSTANT)
    Q_PROPERTY(QString bpp READ Bpp CONSTANT)
    Q_PROPERTY(QString shareFolder READ ShareFolder CONSTANT)
    Q_PROPERTY(QString throttleMultiplier READ ThrottleMultiplier CONSTANT)
    Q_PROPERTY(QString cpuRateMultiplier READ CpuRateMultiplier CONSTANT)
    Q_PROPERTY(QString doubleTapHelper READ DoubleTapHelper CONSTANT)
    Q_PROPERTY(QString boardPage READ BoardPage CONSTANT)
    Q_PROPERTY(QString guestAdditionsPage READ GuestAdditionsPage CONSTANT)
    Q_PROPERTY(QString displayPage READ DisplayPage CONSTANT)
    Q_PROPERTY(QString cpuConfigPage READ CpuConfigPage CONSTANT)
    Q_PROPERTY(QString emulatorPage READ EmulatorPage CONSTANT)
    Q_PROPERTY(QString settingsEmulatorPage READ SettingsEmulatorPage CONSTANT)
    Q_PROPERTY(QString settingsFeedbackPage READ SettingsFeedbackPage CONSTANT)
    Q_PROPERTY(QString settingsAboutPage READ SettingsAboutPage CONSTANT)

public:
    using QObject::QObject;

    QString BoardId() const;
    QString Name() const;
    QString Rom() const;
    QString Storage() const;
    QString GuestAdditions() const;
    QString NetworkEnabled() const;
    QString ColorScheme() const;
    QString FullScreen() const;
    QString Dpi() const;
    QString FontSize() const;
    QString ClearType() const;
    QString AllowUntrustedApps() const;
    QString Bpp() const;
    QString ShareFolder() const;
    QString ThrottleMultiplier() const;
    QString CpuRateMultiplier() const;
    QString DoubleTapHelper() const;
    QString BoardPage() const;
    QString GuestAdditionsPage() const;
    QString DisplayPage() const;
    QString CpuConfigPage() const;
    QString EmulatorPage() const;
    QString SettingsEmulatorPage() const;
    QString SettingsFeedbackPage() const;
    QString SettingsAboutPage() const;
};
