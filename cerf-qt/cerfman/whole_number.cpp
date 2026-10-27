#include "whole_number.h"

#include <cmath>

bool IsWholeNumber(double number) { return std::floor(number) == number; }
