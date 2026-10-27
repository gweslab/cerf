#pragma once

#include "canvas_input.h"

#include <Qt>

#include <cstdint>

uint32_t                  HeldMouseButtons(Qt::MouseButtons buttons);
cerffrontend::MouseButton CanvasMouseButton(Qt::MouseButton button);
