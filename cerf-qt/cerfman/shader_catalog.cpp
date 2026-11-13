#include "shader_catalog.h"

#include "../shader_library_path.h"
#include "../shader_selection.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QDir>
#include <QDirIterator>
#include <QFileInfo>

#include <string>
#include <vector>

REGISTER_SERVICE(ShaderCatalog);

void ShaderCatalog::Changed() {
    ++revision_;
    emit revisionChanged();
}

QStringList ShaderCatalog::PresetPaths(const QString& root) {
    QStringList  paths;
    QDirIterator it(root, {QStringLiteral("*.slangp")}, QDir::Files, QDirIterator::Subdirectories);
    while (it.hasNext()) paths.append(it.next());
    return paths;
}

QVariantList ShaderCatalog::Presets() const {
    const QDir  root(QString::fromStdString(cerffrontend::ShaderSelection::Directory()));
    QStringList paths;
    for (const QString& path : PresetPaths(root.path())) paths.append(root.relativeFilePath(path));
    paths.sort(Qt::CaseInsensitive);
    QVariantList presets;
    for (const QString& path : paths) {
        const QFileInfo info(path);
        presets.append(QVariantMap{{QStringLiteral("path"), path},
                                   {QStringLiteral("name"), info.completeBaseName()},
                                   {QStringLiteral("folder"), info.path()}});
    }
    return presets;
}

QVariantMap ShaderCatalog::Inspect(const QStringList& chain) {
    QVariantList parameters;
    std::string  error;
    if (!chain.isEmpty() && (library_.Loaded() || library_.Load(ShaderPresetRuntime(), error))) {
        const std::string            directory = cerffrontend::ShaderSelection::Directory();
        std::vector<std::string>     presets;
        std::vector<ShaderParameter> found;
        for (const QString& preset : chain) presets.push_back(directory + preset.toStdString());
        if (library_.Parameters(presets, found, error))
            for (const ShaderParameter& p : found)
                parameters.append(QVariantMap{{QStringLiteral("name"), QString::fromStdString(p.name)},
                                              {QStringLiteral("description"), QString::fromStdString(p.description)},
                                              {QStringLiteral("initial"), p.initial},
                                              {QStringLiteral("minimum"), p.minimum},
                                              {QStringLiteral("maximum"), p.maximum},
                                              {QStringLiteral("step"), p.step}});
    }
    return QVariantMap{{QStringLiteral("parameters"), parameters},
                       {QStringLiteral("error"), QString::fromStdString(error)}};
}
