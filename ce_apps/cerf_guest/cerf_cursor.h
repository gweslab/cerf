#pragma once

#include <windows.h>

extern "C" void CerfPublishCursor(const void* mask_bits, int stride,
                                  int cx, int cy, int xhot, int yhot, BOOL visible);
