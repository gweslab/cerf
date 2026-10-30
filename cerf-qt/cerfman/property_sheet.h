#pragma once

#include "device_directory.h"
#include "json_file.h"

#include <QObject>
#include <QSize>
#include <QString>
#include <QVariant>
#include <QVariantList>
#include <QVariantMap>

#include <optional>

namespace cerfcore {
class CerfEmulator;
}

struct PropertySubject {
    DeviceDirectory    device;
    QString            display_name;
    int                os_ver_major = 0;
    bool               forbid_guest_additions = false;
    std::optional<int> default_width;
    std::optional<int> default_height;

    static PropertySubject OfDirectory(const QString& path);
};

class PropertySheet : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString title READ Title CONSTANT)
    Q_PROPERTY(bool editable READ Editable CONSTANT)
    Q_PROPERTY(bool live READ Live CONSTANT)
    Q_PROPERTY(bool locked READ Locked CONSTANT)
    Q_PROPERTY(QString initialPage READ InitialPage CONSTANT)
    Q_PROPERTY(QString deviceDirectory READ DeviceDirectoryPath CONSTANT)
    Q_PROPERTY(bool forceReboot READ ForceReboot CONSTANT)
    Q_PROPERTY(bool fullScreenSetting READ FullScreenSetting CONSTANT)
    Q_PROPERTY(bool doubleTapHelperSetting READ DoubleTapHelperSetting CONSTANT)
    Q_PROPERTY(QString mountPointDefault READ MountPointDefault CONSTANT)
    Q_PROPERTY(QVariantMap values READ Values NOTIFY valuesChanged)
    Q_PROPERTY(bool guestAdditions READ GuestAdditionsOn NOTIFY valuesChanged)
    Q_PROPERTY(bool fullScreen READ FullScreen NOTIFY valuesChanged)
    Q_PROPERTY(bool networkEnabled READ NetworkEnabled NOTIFY valuesChanged)
    Q_PROPERTY(bool doubleTapHelper READ DoubleTapHelper NOTIFY valuesChanged)
    Q_PROPERTY(QVariant hud READ Hud NOTIFY valuesChanged)
    Q_PROPERTY(bool allowUntrustedApps READ AllowUntrustedApps NOTIFY valuesChanged)
    Q_PROPERTY(QString boardId READ BoardId NOTIFY valuesChanged)
    Q_PROPERTY(QVariant resolution READ Resolution NOTIFY valuesChanged)
    Q_PROPERTY(QString shareFolder READ ShareFolder NOTIFY valuesChanged)
    Q_PROPERTY(QString mountPoint READ MountPoint NOTIFY valuesChanged)
    Q_PROPERTY(QVariantMap cpuOverrides READ CpuOverrides NOTIFY valuesChanged)
    Q_PROPERTY(QVariant cpuPreset READ CpuPreset NOTIFY valuesChanged)
    Q_PROPERTY(QVariantList pages READ Pages NOTIFY valuesChanged)
    Q_PROPERTY(QVariantList preview READ Preview NOTIFY valuesChanged)
    Q_PROPERTY(QSize autoSize READ AutoSize NOTIFY valuesChanged)
    Q_PROPERTY(int autoDepth READ AutoDepth NOTIFY valuesChanged)
    Q_PROPERTY(bool rebootRequired READ RebootRequired NOTIFY valuesChanged)
    Q_PROPERTY(QVariantList resetChoices READ ResetChoices CONSTANT)
    Q_PROPERTY(QString noReset READ NoReset CONSTANT)
    Q_PROPERTY(QString softReset READ SoftReset CONSTANT)

public:
    static constexpr char kModeEdit[]   = "edit";
    static constexpr char kModeLocked[] = "locked";
    static constexpr char kModeLive[]   = "live";

    PropertySheet(cerfcore::CerfEmulator& emu, PropertySubject subject, QString mode,
                  QString initial_page, std::optional<int> ce_major, bool force_reboot,
                  QObject* parent = nullptr);

    QString      Title() const;
    bool         Editable() const { return mode_ == QLatin1String(kModeEdit); }
    bool         Live() const { return mode_ == QLatin1String(kModeLive); }
    bool         Locked() const { return mode_ == QLatin1String(kModeLocked); }
    QString      InitialPage() const { return initial_page_; }
    QString      DeviceDirectoryPath() const { return subject_.device.Path(); }
    bool         ForceReboot() const { return force_reboot_; }
    bool         FullScreenSetting() const;
    bool         DoubleTapHelperSetting() const;
    QString      MountPointDefault() const;
    QVariantMap  Values() const;
    bool         GuestAdditionsOn() const;
    bool         FullScreen() const;
    bool         NetworkEnabled() const;
    bool         DoubleTapHelper() const;
    QVariant     Hud() const;
    bool         AllowUntrustedApps() const;
    QString      BoardId() const;
    QVariant     Resolution() const;
    QString      ShareFolder() const;
    QString      MountPoint() const;
    QVariantMap  CpuOverrides() const;
    QVariant     CpuPreset() const;
    QVariantList Pages() const;
    QVariantList Preview() const;
    QSize        AutoSize() const;
    int          AutoDepth() const;
    bool         RebootRequired() const;
    QVariantList ResetChoices() const;
    QString      NoReset() const;
    QString      SoftReset() const;

    const Json& Data() const { return values_; }
    QVariantMap BoardCpuOverrides() const;

    Q_INVOKABLE void         SetValue(const QString& key, const QVariant& value);
    Q_INVOKABLE void         ClearValue(const QString& key);
    Q_INVOKABLE void         SetOrClear(const QString& key, const QVariant& value);
    Q_INVOKABLE void         SetResolution(const QVariant& size);
    Q_INVOKABLE QVariantList ResolutionForPrompt() const;
    Q_INVOKABLE int          DpiForPrompt() const;
    Q_INVOKABLE void         ApplyScalePreset(int index);
    Q_INVOKABLE void         SetMountPoint(const QString& name);
    Q_INVOKABLE void         SetCpuOverride(const QString& param_id, const QVariant& value);
    Q_INVOKABLE void         ApplyCpuPreset(const QVariant& choice);
    Q_INVOKABLE QVariantMap  Problem() const;
    Q_INVOKABLE QString      Save();
    Q_INVOKABLE void         Finish(const QString& reboot);
    Q_INVOKABLE void         Cancel();

signals:
    void valuesChanged();
    void finished(bool accepted, const QString& reboot);

private:
    bool    GuestAdditionsAvailable(const QString& board_id) const;
    bool    Flag(const char* key) const;
    Json    BoardCpuOverrideJson() const;
    QString SaveOwned(bool all);

    cerfcore::CerfEmulator& emu_;
    PropertySubject         subject_;
    QString                 mode_;
    QString                 initial_page_;
    std::optional<int>      ce_major_;
    bool                    force_reboot_;
    Json                    baseline_;
    Json                    values_;
    Json                    initial_;
};
