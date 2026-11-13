#include "shader_library_path.h"

#include <QCoreApplication>

QString ShaderLibraryPath(const char* runtime) {
    return QCoreApplication::applicationDirPath() + QStringLiteral("/librashader_%1.dll").arg(QLatin1String(runtime));
}

const char* ShaderPresetRuntime() { return "gl"; }
