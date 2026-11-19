#include "automation_server.h"

#include "../automation_option.h"
#include "../frontend_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/fatal.h>
#include <cerfcore/core/log.h>
#include <cerfcore/platform/host_process.h>

#include <QLocalServer>
#include <QLocalSocket>
#include <QMetaObject>
#include <QString>

#include <utility>

namespace cerffrontend {

REGISTER_SERVICE_AS(AutomationServer, AutomationEndpoint);

namespace {

constexpr int kNameProbeMs = 1000;

AutomationJson ErrorMessage(const AutomationJson& id, int code, const std::string& message) {
    return AutomationJson{{"jsonrpc", "2.0"}, {"id", id}, {"error", {{"code", code}, {"message", message}}}};
}

AutomationJson ParamJson(const AutomationParam& param) {
    return AutomationJson{{"name", param.name},
                          {"type", param.type},
                          {"required", param.required},
                          {"description", param.description}};
}

}

AutomationCall::AutomationCall(AutomationServer& server, uint64_t connection, AutomationJson id,
                               AutomationJson params)
    : server_(&server), connection_(connection), id_(std::move(id)), params_(std::move(params)) {}

void AutomationCall::Reply(AutomationJson result) const {
    if (id_.is_null()) return;
    server_->Send(connection_, AutomationJson{{"jsonrpc", "2.0"}, {"id", id_}, {"result", std::move(result)}});
}

void AutomationCall::Fail(int code, const std::string& message) const {
    if (id_.is_null()) return;
    server_->Send(connection_, ErrorMessage(id_, code, message));
}

bool AutomationServer::ShouldRegister() { return AutomationRequested(emu_.Argc(), emu_.Argv()); }

std::string AutomationServer::EndpointName() const {
    std::string name;
    std::string chosen;
    for (int i = 1; i < emu_.Argc(); ++i) {
        switch (ReadAutomationArgument(emu_.Argv()[i], name)) {
            case AutomationArgument::kUnnamed:
                chosen = "cerf-automation-" + std::to_string(cerfcore::host_platform::CurrentProcessId());
                break;
            case AutomationArgument::kNamed:
                chosen = name;
                break;
            case AutomationArgument::kOther:
            case AutomationArgument::kInvalid:
                break;
        }
    }
    return chosen;
}

void AutomationServer::OnReady() {
    AddMethod("describe", "Lists every method with its parameters, and every event topic.", {},
              "object", [this](const AutomationCall& call) { call.Reply(Describe()); });
    AddMethod("events.subscribe",
              "Starts the events of the named topics on this connection. The result holds the current state of "
              "each topic that has one.",
              {{"topics", "string[]", true, "topic names from describe"}}, "topic name -> current state or null",
              [this](const AutomationCall& call) { Watch(call, true); });
    AddMethod("events.unsubscribe", "Stops the events of the named topics on this connection.",
              {{"topics", "string[]", true, "topic names from describe"}}, "empty object",
              [this](const AutomationCall& call) { Watch(call, false); });
    emu_.Get<FrontendWindow>().RunOnUiThread([this] { Listen(); });
}

void AutomationServer::Listen() {
    const QString name  = QString::fromStdString(EndpointName());
    auto&         fatal = emu_.Get<cerfcore::Fatal>();
    QLocalSocket  probe;
    probe.connectToServer(name);
    if (probe.waitForConnected(kNameProbeMs))
        fatal.UserError("The automation endpoint %s did not open. Another instance uses this name. Start with "
                        "another --automation name.",
                        name.toStdString().c_str());
    QLocalServer::removeServer(name);
    listener_ = new QLocalServer();
    listener_->setSocketOptions(QLocalServer::UserAccessOption);
    if (!listener_->listen(name))
        fatal.UserError("The automation endpoint %s cannot listen: %s", name.toStdString().c_str(),
                        listener_->errorString().toStdString().c_str());
    {
        std::lock_guard<std::mutex> lk(address_mtx_);
        address_ = listener_->fullServerName().toStdString();
    }
    LOG(Automation, "listening on %s\n", Address().c_str());
    QObject::connect(listener_, &QLocalServer::newConnection, listener_, gate_.Bind([this] { Accept(); }));
}

void AutomationServer::OnShutdown() {
    for (auto& [id, client] : clients_) {
        QObject::disconnect(client.socket, nullptr, nullptr, nullptr);
        delete client.socket;
    }
    clients_.clear();
    delete listener_;
    listener_ = nullptr;
}

std::string AutomationServer::Address() const {
    std::lock_guard<std::mutex> lk(address_mtx_);
    return address_;
}

void AutomationServer::AddMethod(std::string name, std::string description, std::vector<AutomationParam> params,
                                 std::string result, Handler handler) {
    methods_[std::move(name)] = Method{std::move(description), std::move(params), std::move(result), std::move(handler)};
}

size_t AutomationServer::AddTopic(std::string name, std::string description, Payload snapshot) {
    topics_.push_back(Topic{std::move(name), std::move(description), std::move(snapshot)});
    watchers_.emplace_back(0);
    return topics_.size() - 1;
}

bool AutomationServer::Watched(size_t topic) const { return watchers_[topic].load(std::memory_order_acquire) > 0; }

void AutomationServer::Publish(size_t topic, Payload payload) {
    if (!Watched(topic)) return;
    emu_.Get<FrontendWindow>().RunOnUiThread([this, topic, payload = std::move(payload)] {
        const AutomationJson message{{"jsonrpc", "2.0"},
                                     {"method", "event"},
                                     {"params", {{"topic", topics_[topic].name}, {"data", payload()}}}};
        for (auto& [id, client] : clients_)
            if (client.topics[topic]) Write(id, message);
    });
}

void AutomationServer::AddDisconnectListener(DisconnectListener listener) {
    disconnect_listeners_.Add(std::move(listener));
}

void AutomationServer::Send(uint64_t connection, AutomationJson message) {
    emu_.Get<FrontendWindow>().RunOnUiThread(
        [this, connection, message = std::move(message)] { Write(connection, message); });
}

void AutomationServer::Accept() {
    while (QLocalSocket* socket = listener_->nextPendingConnection()) {
        const uint64_t id = next_client_++;
        Client&        client = clients_[id];
        client.socket         = socket;
        client.topics.assign(topics_.size(), false);
        QObject::connect(socket, &QLocalSocket::readyRead, socket, gate_.Bind([this, id] { Receive(id); }));
        QObject::connect(socket, &QLocalSocket::disconnected, socket, gate_.Bind([this, id] { Drop(id); }));
        LOG(Automation, "client %llu connected\n", static_cast<unsigned long long>(id));
    }
}

void AutomationServer::Receive(uint64_t id) {
    const auto it = clients_.find(id);
    if (it == clients_.end()) return;
    const QByteArray bytes    = it->second.socket->readAll();
    std::string&     received = it->second.received;
    received.append(bytes.constData(), static_cast<size_t>(bytes.size()));
    if (received.size() > kMaxReceivedBytes) {
        LOG(Automation, "client %llu sent a line longer than %zu bytes, disconnecting it\n",
            static_cast<unsigned long long>(id), kMaxReceivedBytes);
        received.clear();
        it->second.socket->abort();
        return;
    }
    std::vector<std::string> lines;
    size_t                   start = 0;
    for (size_t end = received.find('\n'); end != std::string::npos; end = received.find('\n', start)) {
        std::string line = received.substr(start, end - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) lines.push_back(std::move(line));
        start = end + 1;
    }
    received.erase(0, start);
    for (const std::string& line : lines) Dispatch(id, line);
}

void AutomationServer::Dispatch(uint64_t id, const std::string& line) {
    AutomationJson request = AutomationJson::parse(line, nullptr, false);
    if (request.is_discarded() || !request.is_object()) {
        Write(id, ErrorMessage(nullptr, kParseError, "the line is not a JSON object"));
        return;
    }
    const AutomationJson request_id = request.contains("id") ? request["id"] : AutomationJson();
    const auto           method     = request.find("method");
    if (method == request.end() || !method->is_string()) {
        Write(id, ErrorMessage(request_id, kInvalidRequest, "the request has no method name"));
        return;
    }
    const auto found = methods_.find(method->get<std::string>());
    if (found == methods_.end()) {
        Write(id, ErrorMessage(request_id, kMethodNotFound, "unknown method " + method->get<std::string>()));
        return;
    }
    AutomationJson params = request.contains("params") ? request["params"] : AutomationJson::object();
    if (!params.is_object()) {
        Write(id, ErrorMessage(request_id, kInvalidParams, "params must be a JSON object"));
        return;
    }
    const AutomationCall call(*this, id, request_id, std::move(params));
    try {
        found->second.handler(call);
    } catch (const AutomationError& error) {
        call.Fail(error.Code(), error.what());
    }
}

void AutomationServer::Drop(uint64_t id) {
    const auto it = clients_.find(id);
    if (it == clients_.end()) return;
    for (size_t topic = 0; topic < it->second.topics.size(); ++topic)
        if (it->second.topics[topic]) watchers_[topic].fetch_sub(1, std::memory_order_acq_rel);
    QLocalSocket* socket = it->second.socket;
    clients_.erase(it);
    socket->deleteLater();
    LOG(Automation, "client %llu disconnected\n", static_cast<unsigned long long>(id));
    disconnect_listeners_.Call(id);
}

void AutomationServer::Write(uint64_t id, const AutomationJson& message) {
    const auto it = clients_.find(id);
    if (it == clients_.end()) return;
    QLocalSocket* socket = it->second.socket;
    if (socket->state() != QLocalSocket::ConnectedState) return;
    const std::string text = message.dump(-1, ' ', false, AutomationJson::error_handler_t::replace) + "\n";
    socket->write(text.data(), static_cast<qint64>(text.size()));
    if (socket->bytesToWrite() <= kMaxUnsentBytes) return;
    LOG(Automation, "client %llu reads too slowly, disconnecting it\n",
        static_cast<unsigned long long>(id));
    QMetaObject::invokeMethod(
        socket, [abort = gate_.Bind([socket] { socket->abort(); })]() mutable { abort(); }, Qt::QueuedConnection);
}

size_t AutomationServer::TopicIndex(const std::string& name) const {
    for (size_t topic = 0; topic < topics_.size(); ++topic)
        if (topics_[topic].name == name) return topic;
    throw AutomationError(kInvalidParams, "unknown topic " + name);
}

void AutomationServer::Watch(const AutomationCall& call, bool on) {
    const auto topics = call.Params().find("topics");
    if (topics == call.Params().end() || !topics->is_array())
        throw AutomationError(kInvalidParams, "topics must be an array of topic names");
    std::vector<size_t> chosen;
    for (const AutomationJson& name : *topics) {
        if (!name.is_string()) throw AutomationError(kInvalidParams, "topics must be an array of topic names");
        chosen.push_back(TopicIndex(name.get<std::string>()));
    }
    Client&        client = clients_.at(call.Connection());
    AutomationJson result = AutomationJson::object();
    for (size_t topic : chosen) {
        if (client.topics[topic] != on) {
            client.topics[topic] = on;
            watchers_[topic].fetch_add(on ? 1 : -1, std::memory_order_acq_rel);
        }
        if (on) result[topics_[topic].name] = topics_[topic].snapshot ? topics_[topic].snapshot() : AutomationJson();
    }
    call.Reply(std::move(result));
}

AutomationJson AutomationServer::Describe() const {
    AutomationJson methods = AutomationJson::array();
    for (const auto& [name, method] : methods_) {
        AutomationJson params = AutomationJson::array();
        for (const AutomationParam& param : method.params) params.push_back(ParamJson(param));
        methods.push_back(AutomationJson{{"name", name},
                                         {"description", method.description},
                                         {"params", std::move(params)},
                                         {"result", method.result}});
    }
    AutomationJson topics = AutomationJson::array();
    for (const Topic& topic : topics_)
        topics.push_back(AutomationJson{{"name", topic.name}, {"description", topic.description}});
    return AutomationJson{{"protocol", kProtocolVersion}, {"methods", std::move(methods)}, {"topics", std::move(topics)}};
}

}
