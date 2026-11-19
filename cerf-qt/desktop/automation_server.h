#pragma once

#include "../automation_endpoint.h"

#include <cerfcore/core/callback_list.h>
#include <cerfcore/core/instance_gate.h>

#include <nlohmann/json.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <mutex>
#include <stdexcept>
#include <string>
#include <vector>

class QLocalServer;
class QLocalSocket;

namespace cerffrontend {

using AutomationJson = nlohmann::ordered_json;

class AutomationServer;

struct AutomationParam {
    std::string name;
    std::string type;
    bool        required = false;
    std::string description;
};

class AutomationError : public std::runtime_error {
public:
    AutomationError(int code, const std::string& message) : std::runtime_error(message), code_(code) {}
    int Code() const { return code_; }

private:
    int code_;
};

class AutomationCall {
public:
    AutomationCall(AutomationServer& server, uint64_t connection, AutomationJson id, AutomationJson params);

    const AutomationJson& Params() const { return params_; }
    uint64_t              Connection() const { return connection_; }
    void                  Reply(AutomationJson result) const;
    void                  Fail(int code, const std::string& message) const;

private:
    AutomationServer* server_;
    uint64_t          connection_;
    AutomationJson    id_;
    AutomationJson    params_;
};

class AutomationServer : public AutomationEndpoint {
public:
    using AutomationEndpoint::AutomationEndpoint;
    using Handler            = std::function<void(const AutomationCall&)>;
    using Payload            = std::function<AutomationJson()>;
    using DisconnectListener = std::function<void(uint64_t connection)>;

    static constexpr int kProtocolVersion = 1;
    static constexpr int kParseError     = -32700;
    static constexpr int kInvalidRequest = -32600;
    static constexpr int kMethodNotFound = -32601;
    static constexpr int kInvalidParams  = -32602;
    static constexpr int kRefused        = -32000;

    bool        ShouldRegister() override;
    void        OnReady() override;
    void        OnShutdown() override;
    std::string Address() const override;

    void   AddMethod(std::string name, std::string description, std::vector<AutomationParam> params,
                     std::string result, Handler handler);
    size_t AddTopic(std::string name, std::string description, Payload snapshot = {});
    bool   Watched(size_t topic) const;
    void   Publish(size_t topic, Payload payload);
    void   AddDisconnectListener(DisconnectListener listener);
    void   Send(uint64_t connection, AutomationJson message);

private:
    struct Method {
        std::string                  description;
        std::vector<AutomationParam> params;
        std::string                  result;
        Handler                      handler;
    };

    struct Topic {
        std::string name;
        std::string description;
        Payload     snapshot;
    };

    struct Client {
        QLocalSocket*     socket = nullptr;
        std::string       received;
        std::vector<bool> topics;
    };

    static constexpr int64_t kMaxUnsentBytes   = int64_t(64) << 20;
    static constexpr size_t  kMaxReceivedBytes = size_t(16) << 20;

    std::string    EndpointName() const;
    void           Listen();
    void           Accept();
    void           Receive(uint64_t id);
    void           Dispatch(uint64_t id, const std::string& line);
    void           Drop(uint64_t id);
    void           Write(uint64_t id, const AutomationJson& message);
    void           Watch(const AutomationCall& call, bool on);
    size_t         TopicIndex(const std::string& name) const;
    AutomationJson Describe() const;

    const cerfcore::InstanceGate           gate_{emu_};
    QLocalServer*                          listener_ = nullptr;
    std::map<uint64_t, Client>             clients_;
    uint64_t                               next_client_ = 1;
    std::map<std::string, Method>          methods_;
    std::vector<Topic>                     topics_;
    std::deque<std::atomic<int>>           watchers_;
    cerfcore::CallbackList<uint64_t>       disconnect_listeners_;
    mutable std::mutex                     address_mtx_;
    std::string                            address_;
};

}
