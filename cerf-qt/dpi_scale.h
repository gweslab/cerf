#pragma once

namespace cerffrontend {

inline constexpr int kDefaultDpi = 96;

int ScaleForDpi(int value, int dpi);
int IntegerFactorForDpi(int dpi);

}
