#pragma once

#include <cerfcore/core/service.h>
#include <cerfcore/host/prompt_answer.h>

#include <cstdint>
#include <string>

namespace cerffrontend {

enum class YesNoLevel : uint8_t { kPlain, kWarning };
enum class YesNoEnter : uint8_t { kYes, kNo };

class YesNoPrompt : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    cerfcore::PromptAnswer Ask(const std::string& title, const std::string& message, YesNoLevel level,
                               YesNoEnter enter);
};

}
