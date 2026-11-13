#include "shader_library_path.h"

#include <QCoreApplication>

QString ShaderLibraryPath(const char* runtime) {
    return QCoreApplication::applicationDirPath() + QStringLiteral("/lib/librashader_%1.so").arg(QLatin1String(runtime));
}

const char* ShaderPresetRuntime() { return "gl"; }
