#pragma once

#include <cstdint>
#include <functional>

namespace cerffrontend {

class LowLevelKeyboardHook {
public:
    using Handler = std::function<bool(uint32_t vk, bool key_up)>;

    LowLevelKeyboardHook() = default;
    LowLevelKeyboardHook(const LowLevelKeyboardHook&)            = delete;
    LowLevelKeyboardHook& operator=(const LowLevelKeyboardHook&) = delete;

    void Install(Handler handler);
    void Remove();
    bool OnKey(uint32_t vk, bool key_up) const { return handler_(vk, key_up); }

private:
    void*   hook_ = nullptr;
    Handler handler_;
};

}
