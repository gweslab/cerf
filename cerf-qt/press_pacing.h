#pragma once

#include <cstdint>
#include <deque>
#include <unordered_map>

enum class KeyEdge { kDown, kUp, kNone };

class PressPacing {
public:
    static constexpr int64_t kMinPressMs = 100;

    void    Push(int code, KeyEdge edge, bool paced);
    bool    PopReady(int64_t now_ms);
    int64_t HeadDue() const;
    void    Clear();

private:
    struct Pending {
        int     code;
        KeyEdge edge;
        bool    paced;
    };
    struct Press {
        int64_t at_ms;
        bool    paced;
    };

    std::deque<Pending>            pending_;
    std::unordered_map<int, Press> held_;
};
