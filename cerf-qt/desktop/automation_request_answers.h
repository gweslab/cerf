#pragma once

#include "automation_server.h"

#include <cerfcore/core/service.h>
#include <cerfcore/host/machine_requests.h>

#include <atomic>
#include <cstddef>
#include <string>
#include <thread>
#include <vector>

namespace cerfcore {
class MachineObject;
}

namespace cerffrontend {

class AutomationRequestAnswers : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    class Scope {
    public:
        Scope(AutomationRequestAnswers& owner, cerfcore::MachineObject& object, AutomationJson answers);
        ~Scope();
        Scope(const Scope&)            = delete;
        Scope& operator=(const Scope&) = delete;

        AutomationJson Report() const;

    private:
        friend class AutomationRequestAnswers;

        AutomationRequestAnswers& owner_;
        cerfcore::MachineObject*  object_;
        AutomationJson            answers_;
        AutomationJson            answered_ = AutomationJson::array();
        AutomationJson            waiting_  = AutomationJson::array();
        std::string               error_;
    };

    bool ShouldRegister() override;
    void OnReady() override;

private:
    void           OnRequest(const cerfcore::MachineRequest& request);
    bool           AnswerFromScope(const cerfcore::MachineRequest& request);
    AutomationJson RequestJson(const cerfcore::MachineRequest& request);
    void           Reply(const AutomationCall& call);

    std::atomic<Scope*>          scope_{nullptr};
    std::atomic<std::thread::id> scope_thread_{};
    size_t                       request_topic_ = 0;
    size_t                       settled_topic_ = 0;
};

}
