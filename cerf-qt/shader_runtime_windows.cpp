#include "shader_runtime.h"

#include "shader_runtime_d3d11.h"
#include "shader_runtime_gl.h"

#include <QQuickWindow>
#include <QSGRendererInterface>

std::unique_ptr<ShaderRuntime> ShaderRuntime::ForWindow(QQuickWindow* window) {
    switch (window->rendererInterface()->graphicsApi()) {
        case QSGRendererInterface::Direct3D11: return CreateShaderRuntimeD3d11(window);
        case QSGRendererInterface::OpenGL:     return CreateShaderRuntimeGl(window);
        default:                               return nullptr;
    }
}
