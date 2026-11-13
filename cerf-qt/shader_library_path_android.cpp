#include "shader_library_path.h"

QString ShaderLibraryPath(const char* runtime) {
    return QStringLiteral("librashader_%1.so").arg(QLatin1String(runtime));
}

const char* ShaderPresetRuntime() { return "gl"; }
