#include "shader_runtime.h"

#include "shader_runtime_metal.h"

#include <QQuickWindow>
#include <QSGRendererInterface>

std::unique_ptr<ShaderRuntime> ShaderRuntime::ForWindow(QQuickWindow* window) {
    if (window->rendererInterface()->graphicsApi() != QSGRendererInterface::Metal) return nullptr;
    return CreateShaderRuntimeMetal(window);
}
