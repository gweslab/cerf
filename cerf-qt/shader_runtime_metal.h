#pragma once

#include "shader_runtime.h"

#include <memory>

class QQuickWindow;

std::unique_ptr<ShaderRuntime> CreateShaderRuntimeMetal(QQuickWindow* window);
