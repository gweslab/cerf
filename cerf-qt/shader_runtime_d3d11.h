#pragma once

#include "shader_runtime.h"

#include <memory>

class QQuickWindow;

std::unique_ptr<ShaderRuntime> CreateShaderRuntimeD3d11(QQuickWindow* window);
