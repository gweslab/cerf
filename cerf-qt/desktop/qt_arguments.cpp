#include "qt_arguments.h"

#include "utf8_arguments.h"

#include "../main_config.h"

#include <cerfcore/core/cli_option.h>

#include <algorithm>

namespace {

bool IsDeviceArgument(const char* argument) {
    const char* device = nullptr;
    return cerfcore::ReadCliOption(argument, cerffrontend::kArgDevice, device);
}

}

QtArguments::QtArguments(int argc, char** argv) : utf8_(Utf8Arguments(argc, argv)) {
    for (std::string& argument : utf8_) original_.push_back(argument.data());
    for (char* argument : original_)
        if (!IsDeviceArgument(argument)) qt_.push_back(argument);
    qt_count_ = static_cast<int>(qt_.size());
    qt_.push_back(nullptr);
    kept_ = original_;
    kept_.push_back(nullptr);
}

void QtArguments::KeepWhatQtLeft() {
    kept_.clear();
    for (char* argument : original_)
        if (IsDeviceArgument(argument) || QtKept(argument)) kept_.push_back(argument);
    kept_.push_back(nullptr);
}

bool QtArguments::QtKept(const char* argument) const {
    return std::find(qt_.begin(), qt_.begin() + qt_count_, argument) != qt_.begin() + qt_count_;
}
