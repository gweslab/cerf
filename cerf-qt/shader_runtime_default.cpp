#include "shader_runtime.h"

#include "shader_runtime_gl.h"

#include <QQuickWindow>
#include <QSGRendererInterface>

std::unique_ptr<ShaderRuntime> ShaderRuntime::ForWindow(QQuickWindow* window) {
    if (window->rendererInterface()->graphicsApi() != QSGRendererInterface::OpenGL) return nullptr;
    return CreateShaderRuntimeGl(window);
}
