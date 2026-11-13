#pragma once

#include "manager_qml_engine.h"

#include "../shader_library.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantList>
#include <QVariantMap>
#include <QtQml/qqmlregistration.h>

class ShaderCatalog : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(int revision READ Revision NOTIFY revisionChanged)

public:
    explicit ShaderCatalog(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static ShaderCatalog* create(QQmlEngine* qml, QJSEngine*) { return ManagerQmlEngine::Singleton<ShaderCatalog>(qml); }

    int  Revision() const { return revision_; }
    void Changed();

    Q_INVOKABLE QVariantList Presets() const;
    Q_INVOKABLE QVariantMap  Inspect(const QStringList& chain);

    static QStringList PresetPaths(const QString& root);

signals:
    void revisionChanged();

private:
    ShaderLibrary library_;
    int           revision_ = 0;
};
