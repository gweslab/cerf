#pragma once
#include "service.h"
#include "log.h"
#include "device_config.h"
#include "main_config.h"
#include <memory>
#include <vector>
#include <functional>
#include <cstdint>
#include <atomic>
#include <array>
#include <type_traits>
#include <typeinfo>

class CerfEmulator {
public:
    CerfEmulator(const CerfConfig& config, int argc, char** argv);
    ~CerfEmulator();

    void Boot();
    void Bootstrap();
    void WaitForExit();

    static constexpr int MAX_SERVICES = 512;
    static inline std::atomic<int> s_next_slot_{0};

    template<typename T>
    static int SlotFor() {
        static const int slot = []() {
            int s = s_next_slot_.fetch_add(1, std::memory_order_relaxed);
            if (s >= MAX_SERVICES) {
                LOG(Caution, "Service slot overflow: %d >= MAX_SERVICES %d "
                        "(adding service %s). Raise MAX_SERVICES in cerf_emulator.h.\n",
                        s, MAX_SERVICES, typeid(T).name());
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            return s;
        }();
        return slot;
    }

    template<typename T>
    void Provide(T& instance) {
        const int slot = SlotFor<T>();
        if (services_[slot] != nullptr) {
            LOG(Caution, "Provide<%s>() — slot already occupied. "
                    "Two services claimed the same locator slot; for "
                    "REGISTER_SERVICE_AS this means more than one "
                    "ShouldRegister() returned true for the same Base.\n",
                    typeid(T).name());
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        services_[slot] = static_cast<void*>(&instance);
    }

    template<typename T>
    T& Get() {
        const int slot = SlotFor<T>();
        if (services_[slot] == nullptr) {
            ResolveSlot(slot, typeid(T).name());
            if (services_[slot] == nullptr) {
                LOG(Caution, "Get<%s>() — no candidate's ShouldRegister "
                        "returned true. Either no impl was registered for "
                        "this Base, or every registered impl decided this "
                        "device wasn't its match.\n", typeid(T).name());
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
        }
        T* svc = static_cast<T*>(services_[slot]);
        if constexpr (std::is_base_of_v<Service, T>) {
            svc->EnsureReady();
        }
        return *svc;
    }

    /* Returns nullptr instead of fataling when no candidate's
       ShouldRegister wins. */
    template<typename T>
    T* TryGet() {
        const int slot = SlotFor<T>();
        if (services_[slot] == nullptr) {
            ResolveSlot(slot, typeid(T).name());
            if (services_[slot] == nullptr) return nullptr;
        }
        T* svc = static_cast<T*>(services_[slot]);
        if constexpr (std::is_base_of_v<Service, T>) {
            svc->EnsureReady();
        }
        return svc;
    }

    template<typename Base>
    void AddCandidate(std::unique_ptr<Base> instance, bool fallback = false) {
        static_assert(std::is_base_of_v<Service, Base>,
            "AddCandidate Base must derive from Service.");
        const int slot = SlotFor<Base>();
        Base* base_ptr = instance.release();
        Service* svc_ptr = static_cast<Service*>(base_ptr);
        candidate_slots_[slot].entries.push_back(CandidateEntry{
            std::unique_ptr<Service>(svc_ptr),
            static_cast<void*>(base_ptr),
            fallback
        });
    }

    static void AddServiceFactory(std::function<void(CerfEmulator&)> fn) {
        ServiceFactories().push_back(std::move(fn));
    }
    void CreateAllServices() {
        for (auto& fn : ServiceFactories()) fn(*this);
    }

    /* Forces resolution of every candidate slot — without this,
       slots that nothing else Get<>s stay unresolved and their
       winner's OnReady never runs. */
    void ResolveAllSlots() {
        for (int slot = 0; slot < MAX_SERVICES; ++slot) {
            auto& cs = candidate_slots_[slot];
            if (services_[slot] != nullptr) continue;       /* already won */
            if (cs.entries.empty())          continue;       /* no candidate */
            if (cs.resolved)                 continue;       /* tried, no winner */
            ResolveSlot(slot, "(sweep)");
        }
    }

    const CerfConfig& Config() const { return config_; }
    uint32_t InstanceId() const { return instance_id_; }

private:
    void ResolveSlot(int slot, const char* requester_type_name);

    struct CandidateEntry {
        std::unique_ptr<Service> instance;   /* owns lifetime, calls ~Service */
        void*                    slot_ptr;   /* Base* re-cast to void* */
        bool                     is_fallback;
    };
    struct CandidateSlot {
        std::vector<CandidateEntry> entries;
        bool resolving = false;
        bool resolved  = false;
    };

    std::array<void*, MAX_SERVICES>          services_{};
    std::array<CandidateSlot, MAX_SERVICES>  candidate_slots_{};
    std::vector<std::unique_ptr<Service>>    owned_;
    CerfConfig                               config_;
    int                                      argc_ = 0;
    char**                                   argv_ = nullptr;
    DeviceConfig                             device_config_;
    uint32_t                                 instance_id_;
    static inline std::atomic<uint32_t>      s_next_instance_id_{0};

    static std::vector<std::function<void(CerfEmulator&)>>& ServiceFactories() {
        static std::vector<std::function<void(CerfEmulator&)>> v;
        return v;
    }
};

#define REGISTER_SERVICE(Type) \
    static bool _reg_svc_##Type = (CerfEmulator::AddServiceFactory( \
        [](CerfEmulator& emu) { \
            emu.AddCandidate<Type>(std::make_unique<Type>(emu)); \
        }), true)

#define REGISTER_SERVICE_AS(Type, Base) \
    static bool _reg_svc_##Type = (CerfEmulator::AddServiceFactory( \
        [](CerfEmulator& emu) { \
            emu.AddCandidate<Base>(std::make_unique<Type>(emu)); \
        }), true)

#define REGISTER_SERVICE_AS_FALLBACK(Type, Base) \
    static bool _reg_svc_##Type = (CerfEmulator::AddServiceFactory( \
        [](CerfEmulator& emu) { \
            emu.AddCandidate<Base>(std::make_unique<Type>(emu), true); \
        }), true)
