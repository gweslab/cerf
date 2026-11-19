#include "automation_params.h"
#include "automation_server.h"

#include "../automation_option.h"
#include "../calibration_answers.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/auto_calibration.h>

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <utility>

namespace cerffrontend {

namespace {

using cerfcore::CalibrationResult;
using cerfcore::CalibrationTrigger;

const char* QuestionName(CalibrationQuestion question) {
    switch (question) {
        case CalibrationQuestion::kCalibrate:       return "calibrate";
        case CalibrationQuestion::kPanelResolution: return "panel_resolution";
    }
    return "";
}

const char* TriggerName(CalibrationTrigger trigger) {
    switch (trigger) {
        case CalibrationTrigger::kBootWindow:     return "boot_scan";
        case CalibrationTrigger::kRequest:        return "request";
        case CalibrationTrigger::kGuestAdditions: return "guest_additions";
    }
    return "";
}

const char* ResultName(CalibrationResult result) {
    switch (result) {
        case CalibrationResult::kFinished:           return "finished";
        case CalibrationResult::kFailed:             return "failed";
        case CalibrationResult::kDeclined:           return "declined";
        case CalibrationResult::kAborted:            return "aborted";
        case CalibrationResult::kResolutionSwitched: return "resolution_switched";
    }
    return "";
}

class AutomationCalibration : public CalibrationAnswers {
public:
    using CalibrationAnswers::CalibrationAnswers;

    bool ShouldRegister() override { return AutomationRequested(emu_.Argc(), emu_.Argv()); }

    void OnReady() override {
        auto& server    = emu_.Get<AutomationServer>();
        question_topic_ = server.AddTopic("calibration.question",
                                          "The automatic touch calibration asks a question. Answer it with "
                                          "calibration.answer.",
                                          [this] { return QuestionJson(); });
        result_topic_   = server.AddTopic("calibration", "An automatic touch calibration cycle ended.");
        server.AddMethod("calibration.run",
                         "Runs the automatic touch calibration on the calibration screen of the guest. Replies when "
                         "the cycle ends.",
                         {{"calibrate", "bool", false, "answer to the calibrate question; absent asks the window"},
                          {"panel_resolution", "bool", false,
                           "answer to the panel resolution question; absent asks the window"}},
                         "{trigger: request|boot_scan|guest_additions, "
                         "result: finished|failed|declined|aborted|resolution_switched}",
                         [this](const AutomationCall& call) { Run(call); });
        server.AddMethod("calibration.answer", "Answers the open calibration question.",
                         {{"yes", "bool", true, "the answer"}}, "empty object",
                         [this](const AutomationCall& call) { AnswerQuestion(call); });
        emu_.Get<cerfcore::AutoCalibration>().RegisterResultListener(
            [this, &server](uint64_t cycle, CalibrationTrigger trigger, CalibrationResult result) {
                const AutomationJson data{{"trigger", TriggerName(trigger)}, {"result", ResultName(result)}};
                server.Publish(result_topic_, [data] { return data; });
                std::optional<AutomationCall> call;
                {
                    std::lock_guard<std::mutex> lock(mtx_);
                    const auto it = pending_.find(cycle);
                    if (it == pending_.end()) return;
                    call = it->second;
                    pending_.erase(it);
                }
                call->Reply(data);
            });
    }

    void Opened(CalibrationQuestion question, uint32_t width, uint32_t height, Answer answer) override {
        open_                     = Open{question, width, height, std::move(answer)};
        const AutomationJson data = QuestionJson();
        emu_.Get<AutomationServer>().Publish(question_topic_, [data] { return data; });
    }

    void Closed() override { open_.reset(); }

private:
    struct Open {
        CalibrationQuestion question;
        uint32_t            width;
        uint32_t            height;
        Answer              answer;
    };

    AutomationJson QuestionJson() const {
        if (!open_) return AutomationJson();
        return AutomationJson{
            {"question", QuestionName(open_->question)}, {"width", open_->width}, {"height", open_->height}};
    }

    void Run(const AutomationCall& call) {
        const AutomationParams params(call.Params());
        auto&                  calibration = emu_.Get<cerfcore::AutoCalibration>();
        if (!calibration.CanPress())
            throw AutomationError(AutomationServer::kRefused, "this device has no touch input to calibrate");
        const cerfcore::CalibrationRequest request{.trigger          = CalibrationTrigger::kRequest,
                                                   .calibrate        = params.OptionalBoolean("calibrate"),
                                                   .panel_resolution = params.OptionalBoolean("panel_resolution"),
                                                   .host_notices     = false};
        std::lock_guard<std::mutex>   lock(mtx_);
        const std::optional<uint64_t> cycle = calibration.Request(request);
        if (!cycle) throw AutomationError(AutomationServer::kRefused, "a calibration cycle already runs");
        pending_.emplace(*cycle, call);
    }

    void AnswerQuestion(const AutomationCall& call) {
        const bool yes = AutomationParams(call.Params()).Boolean("yes");
        if (!open_) throw AutomationError(AutomationServer::kRefused, "no calibration question is open");
        const Answer answer = open_->answer;
        open_.reset();
        answer(yes);
        call.Reply(AutomationJson::object());
    }

    std::mutex                         mtx_;
    std::optional<Open>                open_;
    std::map<uint64_t, AutomationCall> pending_;
    size_t                             question_topic_ = 0;
    size_t                             result_topic_   = 0;
};

}

REGISTER_SERVICE_AS(AutomationCalibration, CalibrationAnswers);

}
