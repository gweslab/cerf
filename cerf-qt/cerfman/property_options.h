#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QSize>
#include <QString>
#include <QVariant>
#include <QVariantList>
#include <QtQml/qqmlregistration.h>

struct ScaleSetting {
    int  dpi;
    int  font_size;
    bool cleartype;
};

class PropertyOptions : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(QString customChoice READ CustomChoice CONSTANT)

public:
    explicit PropertyOptions(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static PropertyOptions* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<PropertyOptions>(qml);
    }

    Q_INVOKABLE QVariantList ResolutionChoices() const;
    Q_INVOKABLE QString      ResolutionChoiceLabel(const QVariant& choice, const QSize& auto_size) const;
    Q_INVOKABLE QVariantList DpiChoices() const;
    Q_INVOKABLE QString      DpiLabel(const QVariant& dpi) const;
    Q_INVOKABLE QVariantList FontSizeChoices() const;
    Q_INVOKABLE QString      FontSizeLabel(const QVariant& size) const;
    Q_INVOKABLE QVariantList BppChoices() const;
    Q_INVOKABLE QString      BppLabel(const QVariant& value, int auto_depth) const;
    Q_INVOKABLE QString      BppHelpText() const;
    Q_INVOKABLE QVariantList CleartypeChoices() const;
    Q_INVOKABLE QString      CleartypeLabel(const QVariant& value) const;
    Q_INVOKABLE QVariantList ColorSchemeKeys() const;
    Q_INVOKABLE QString      ColorSchemeLabel(const QString& key) const;
    Q_INVOKABLE QVariantList ScalePresetIndexes() const;
    Q_INVOKABLE QString      ScalePresetLabel(int index) const;
    Q_INVOKABLE int          ScalePresetIndex(const QVariant& dpi, const QVariant& font_size,
                                              const QVariant& cleartype) const;
    Q_INVOKABLE QVariantList MultiplierChoices(const QString& key) const;
    Q_INVOKABLE QVariant     MultiplierChoice(const QVariant& value) const;
    Q_INVOKABLE QString      MultiplierLabel(const QVariant& value) const;
    Q_INVOKABLE bool         MountPointValid(const QString& name) const;
    Q_INVOKABLE QString      MountPointPath(const QString& name) const;
    Q_INVOKABLE QString      MountPointName(const QString& path) const;
    Q_INVOKABLE int          ConfigIntegerMaximum() const;

    QString                     CustomChoice() const;
    QString                     ResolutionLabel(const QVariant& width, const QVariant& height,
                                                const QSize& auto_size) const;
    int                         DefaultDpi() const;
    ScaleSetting ScalePresetAt(int index) const;
    QString      MountPointInvalidMessage() const;
};
