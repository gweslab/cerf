#include "shader_library_path.h"

#include <QCoreApplication>

QString ShaderLibraryPath(const char* runtime) {
    return QCoreApplication::applicationDirPath() +
           QStringLiteral("/../Frameworks/librashader_%1.dylib").arg(QLatin1String(runtime));
}

const char* ShaderPresetRuntime() { return "metal"; }
