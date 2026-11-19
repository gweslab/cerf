#pragma once

#include <cerfcore/core/service.h>

#include <cstdint>
#include <functional>
#include <string>

class QObject;

namespace cerffrontend {

enum class YesNoLevel : uint8_t { kPlain, kWarning };
enum class YesNoEnter : uint8_t { kYes, kNo };
enum class PromptAnswer : uint8_t { kYes, kNo, kClosed };

class YesNoPrompt : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    PromptAnswer Ask(const std::string& title, const std::string& message, YesNoLevel level, YesNoEnter enter,
                     const std::function<void(QObject*)>& opened = {});
};

}
