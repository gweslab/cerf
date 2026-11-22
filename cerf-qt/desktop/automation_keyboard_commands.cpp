#include "automation_params.h"
#include "automation_server.h"

#include "../automation_option.h"
#include "../host_holds_release.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/service.h>
#include <cerfcore/host/character_keys.h>
#include <cerfcore/host/keyboard_router.h>
#include <cerfcore/host/virtual_key_names.h>

#include <QList>
#include <QString>

#include <cstdint>
#include <map>
#include <optional>
#include <string>

namespace cerffrontend {

namespace {

constexpr int64_t kLastVirtualKey = 0xFE;

class AutomationKeyboardCommands : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool ShouldRegister() override { return AutomationRequested(emu_.Argc(), emu_.Argv()); }

    void OnReady() override {
        auto&                 server = emu_.Get<AutomationServer>();
        const AutomationParam key{"key", "int|string", true,
                                  "a Windows virtual-key code from 1 to 254, or its name such as VK_RETURN"};
        const AutomationParam stock{"stock", "bool", false,
                                    "true sends the key to the stock keyboard of the device"};
        server.AddMethod("keyboard.press", "Presses a key and holds it until keyboard.release.", {key, stock},
                         "empty object", [this](const AutomationCall& call) { Key(call, false); });
        server.AddMethod("keyboard.release", "Releases a key that this connection pressed.", {key}, "empty object",
                         [this](const AutomationCall& call) { Key(call, true); });
        server.AddMethod("keyboard.keys_for_text",
                         "Gives the keys that type a text on the device, one for each character.",
                         {{"text", "string", true, "the text"}}, "array of {vk, shift}",
                         [](const AutomationCall& call) { KeysForText(call); });
        server.AddMethod("keyboard.ctrl_alt_del", "Sends Ctrl+Alt+Del to the guest.", {}, "empty object",
                         [this](const AutomationCall& call) {
                             emu_.Get<cerfcore::KeyboardRouter>().SendCtrlAltDel();
                             call.Reply(AutomationJson::object());
                         });
        server.AddDisconnectListener([this](uint64_t connection) { ReleaseAll(connection); });
        emu_.Get<HostHoldsRelease>().Add([this] {
            while (!held_.empty()) ReleaseAll(held_.begin()->first);
        });
    }

private:
    static uint8_t KeyOf(const AutomationParams& params) {
        const AutomationJson* key = params.Find("key");
        if (key != nullptr && key->is_number_integer()) {
            const int64_t vk = key->get<int64_t>();
            if (vk >= 1 && vk <= kLastVirtualKey) return static_cast<uint8_t>(vk);
        }
        if (key != nullptr && key->is_string()) {
            if (const std::optional<uint8_t> vk = cerfcore::VirtualKeyByName(key->get<std::string>())) return *vk;
        }
        throw AutomationError(AutomationServer::kInvalidParams,
                              "key must be a virtual-key code from 1 to 254 or a known key name");
    }

    void Key(const AutomationCall& call, bool key_up) {
        const AutomationParams params(call.Params());
        const uint8_t          vk   = KeyOf(params);
        auto&                  keys = held_[call.Connection()];
        bool                   stock = params.OptionalBoolean("stock").value_or(false);
        if (key_up) {
            const auto held = keys.find(vk);
            if (held == keys.end())
                throw AutomationError(AutomationServer::kRefused, "this connection does not hold that key");
            stock = held->second;
            keys.erase(held);
        } else {
            if (keys.count(vk) != 0)
                throw AutomationError(AutomationServer::kRefused, "this connection already holds that key");
            keys[vk] = stock;
        }
        Send(vk, key_up, stock);
        call.Reply(AutomationJson::object());
    }

    void Send(uint8_t vk, bool key_up, bool stock) {
        auto& router = emu_.Get<cerfcore::KeyboardRouter>();
        if (stock) router.OnStockKey(vk, key_up);
        else       router.OnHostKey(vk, key_up);
    }

    static void KeysForText(const AutomationCall& call) {
        const QList<uint> characters = QString::fromStdString(AutomationParams(call.Params()).String("text")).toUcs4();
        AutomationJson    keys       = AutomationJson::array();
        for (qsizetype i = 0; i < characters.size(); ++i) {
            cerfcore::TypedKey key;
            if (!cerfcore::KeyForCharacter(static_cast<char32_t>(characters[i]), key))
                throw AutomationError(AutomationServer::kRefused,
                                      "character " + std::to_string(i) + " of the text has no key on the device");
            keys.push_back(AutomationJson{{"vk", key.vk}, {"shift", key.shift}});
        }
        call.Reply(std::move(keys));
    }

    void ReleaseAll(uint64_t connection) {
        const auto it = held_.find(connection);
        if (it == held_.end()) return;
        const std::map<uint8_t, bool> keys = it->second;
        held_.erase(it);
        for (const auto& [vk, stock] : keys) Send(vk, true, stock);
    }

    std::map<uint64_t, std::map<uint8_t, bool>> held_;
};

}

REGISTER_SERVICE(AutomationKeyboardCommands);

}
