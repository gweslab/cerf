#pragma once

#include "qt_key_input.h"

#include <cstdint>

class QKeyEvent;

enum class KeyPositionResult { kMapped, kNoPosition, kNoVirtualKey };

KeyPositionResult HostKeyPosition(const QKeyEvent* event, QtHostKey& out, uint32_t& native);
