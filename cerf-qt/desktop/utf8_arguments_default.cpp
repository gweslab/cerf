#include "utf8_arguments.h"

std::vector<std::string> Utf8Arguments(int argc, char** argv) { return {argv, argv + argc}; }
