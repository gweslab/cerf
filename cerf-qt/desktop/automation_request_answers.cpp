#include "automation_request_answers.h"

#include "automation_object_state.h"
#include "automation_params.h"

#include "../automation_option.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/host/machine_object.h>

#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(AutomationRequestAnswers);

namespace {

const char* KindName(cerfcore::MachineRequestKind kind) {
    switch (kind) {
        case cerfcore::MachineRequestKind::kPath:       return "path";
        case cerfcore::MachineRequestKind::kDocuments:  return "documents";
        case cerfcore::MachineRequestKind::kSize:       return "size";
        case cerfcore::MachineRequestKind::kOutputPath: return "output_path";
    }
    return "";
}

bool FillReply(cerfcore::MachineRequestKind kind, const AutomationJson& value, cerfcore::MachineReply& reply) {
    reply.cancelled = false;
    switch (kind) {
        case cerfcore::MachineRequestKind::kPath:
        case cerfcore::MachineRequestKind::kOutputPath:
            if (!value.is_string()) return false;
            reply.path = value.get<std::string>();
            return true;
        case cerfcore::MachineRequestKind::kDocuments:
            if (!value.is_array()) return false;
            for (const AutomationJson& item : value) {
                if (!item.is_string()) return false;
                reply.documents.push_back(item.get<std::string>());
            }
            return true;
        case cerfcore::MachineRequestKind::kSize:
            if (!value.is_number_unsigned()) return false;
            reply.size = value.get<uint64_t>();
            return true;
    }
    return false;
}

bool PathsAbsolute(const cerfcore::MachineReply& reply) {
    if (!reply.path.empty() && !cerfcore::IsAbsoluteHostPath(reply.path)) return false;
    for (const std::string& document : reply.documents)
        if (!cerfcore::IsAbsoluteHostPath(document)) return false;
    return true;
}

}

AutomationRequestAnswers::Scope::Scope(AutomationRequestAnswers& owner, cerfcore::MachineObject& object,
                                       AutomationJson answers)
    : owner_(owner), object_(&object), answers_(std::move(answers)) {
    owner_.scope_thread_.store(std::this_thread::get_id(), std::memory_order_release);
    owner_.scope_.store(this, std::memory_order_release);
}

AutomationRequestAnswers::Scope::~Scope() {
    owner_.scope_.store(nullptr, std::memory_order_release);
    owner_.scope_thread_.store(std::thread::id(), std::memory_order_release);
}

AutomationJson AutomationRequestAnswers::Scope::Report() const {
    if (!error_.empty()) throw AutomationError(AutomationServer::kRefused, error_);
    return AutomationJson{{"answered", answered_}, {"waiting", waiting_}};
}

bool AutomationRequestAnswers::ShouldRegister() { return AutomationRequested(emu_.Argc(), emu_.Argv()); }

void AutomationRequestAnswers::OnReady() {
    auto& server   = emu_.Get<AutomationServer>();
    request_topic_ = server.AddTopic("request", "The device asks for input. Answer it with requests.reply.");
    settled_topic_ = server.AddTopic("request.settled", "A request was answered or cancelled.");
    server.AddMethod("requests.reply", "Answers a request that a request event announced.",
                     {{"serial", "int", true, "the serial of the request"},
                      {"cancelled", "bool", false, "true cancels the command that asked"},
                      {"path", "string", false, "for a path or output_path request"},
                      {"documents", "string[]", false, "for a documents request"},
                      {"size", "int", false, "for a size request, inside its minimum and maximum"}},
                     "empty object", [this](const AutomationCall& call) { Reply(call); });
    auto& requests = emu_.Get<cerfcore::MachineRequests>();
    requests.Subscribe([this](const cerfcore::MachineRequest& request) { OnRequest(request); });
    requests.SubscribeSettled([this, &server](uint64_t serial) {
        server.Publish(settled_topic_, [serial] { return AutomationJson{{"serial", serial}}; });
    });
}

void AutomationRequestAnswers::OnRequest(const cerfcore::MachineRequest& request) {
    if (AnswerFromScope(request)) return;
    emu_.Get<AutomationServer>().Publish(request_topic_, [this, request] { return RequestJson(request); });
}

bool AutomationRequestAnswers::AnswerFromScope(const cerfcore::MachineRequest& request) {
    if (scope_thread_.load(std::memory_order_acquire) != std::this_thread::get_id()) return false;
    Scope* scope = scope_.load(std::memory_order_acquire);
    if (scope == nullptr || request.object != scope->object_) return false;
    const auto answer = scope->answers_.find(request.id);
    if (answer == scope->answers_.end()) {
        scope->waiting_.push_back(RequestJson(request));
        return false;
    }
    cerfcore::MachineReply reply;
    auto&                  requests = emu_.Get<cerfcore::MachineRequests>();
    if (!FillReply(request.kind, *answer, reply)) {
        scope->error_ = "the answer for " + request.id + " has the wrong type for a " + KindName(request.kind) + " request";
        requests.Reply(request.serial, cerfcore::MachineReply{});
        return true;
    }
    if (!PathsAbsolute(reply)) {
        scope->error_ = "the answer for " + request.id + " must hold absolute paths";
        requests.Reply(request.serial, cerfcore::MachineReply{});
        return true;
    }
    scope->answered_.push_back(request.id);
    if (!requests.Reply(request.serial, reply)) {
        scope->error_ = "the answer for " + request.id + " is outside the limits of the request";
        requests.Reply(request.serial, cerfcore::MachineReply{});
    }
    return true;
}

AutomationJson AutomationRequestAnswers::RequestJson(const cerfcore::MachineRequest& request) {
    return AutomationJson{{"serial", request.serial},
                          {"kind", KindName(request.kind)},
                          {"id", request.id},
                          {"object", emu_.Get<AutomationObjectState>().PathJson(*request.object)},
                          {"extensions", request.extensions},
                          {"minimum", request.minimum},
                          {"maximum", request.maximum},
                          {"recommended", request.recommended},
                          {"recommended_path", request.recommended_path}};
}

void AutomationRequestAnswers::Reply(const AutomationCall& call) {
    const AutomationParams params(call.Params());
    const int64_t          serial = params.Integer("serial");
    cerfcore::MachineReply reply;
    reply.cancelled = params.OptionalBoolean("cancelled").value_or(false);
    if (!reply.cancelled) {
        reply.path = params.OptionalString("path").value_or("");
        if (params.Find("documents") != nullptr) reply.documents = params.Strings("documents");
        if (const std::optional<int64_t> size = params.OptionalInteger("size")) {
            if (*size < 0) throw AutomationError(AutomationServer::kInvalidParams, "size must not be negative");
            reply.size = static_cast<uint64_t>(*size);
        }
        if (!PathsAbsolute(reply)) throw AutomationError(AutomationServer::kInvalidParams, "paths must be absolute");
    }
    if (serial < 0 || !emu_.Get<cerfcore::MachineRequests>().Reply(static_cast<uint64_t>(serial), reply))
        throw AutomationError(AutomationServer::kRefused,
                              "no open request has that serial, or the answer is outside its limits");
    call.Reply(AutomationJson::object());
}

}
