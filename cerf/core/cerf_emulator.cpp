#include "cerf_emulator.h"
#include "log.h"
#include "config_loader.h"
#include "../jit/jit_runner.h"

namespace ServiceInternal {
    [[noreturn]] void HaltOnCycle(const std::type_info& ti) {
        /* Two services depend on each other's OnReady-set state.
           Break by deferring one read to first-use (e.g. from a
           worker thread) instead of doing it at OnReady time. */
        LOG(Caution, "Cycle in service OnReady graph at %s\n",
                ti.name());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
}

CerfEmulator::CerfEmulator(const CerfConfig& config, int argc, char** argv)
    : config_(config), argc_(argc), argv_(argv),
      instance_id_(s_next_instance_id_++)
{
}

CerfEmulator::~CerfEmulator() {
    for (auto it = owned_.rbegin(); it != owned_.rend(); ++it)
        it->reset();
    owned_.clear();
}

void CerfEmulator::Bootstrap() {
    Provide<CerfEmulator>(*this);
    Provide<DeviceConfig>(device_config_);

    ConfigLoader loader(*this);
    loader.Load(config_, argc_, argv_);

    // Before declaringa  service call logic here - what makes your sevice so special
    // that pre-existing OnReady/ShouldRegister that are used in hundreds of services
    // appear to be insufficient for your new logic?
    CreateAllServices();    /* construct all candidates, populate per-slot lists */
    ResolveAllSlots();      /* run ShouldRegister, pick winners, drop losers */

    for (auto& svc : owned_) svc->EnsureReady();
}

void CerfEmulator::ResolveSlot(int slot, const char* requester_type_name) {
    auto& cs = candidate_slots_[slot];
    if (cs.resolved) return;                         /* already tried */
    if (services_[slot] != nullptr) return;          /* already filled */

    if (cs.resolving) {
        LOG(Caution, "ShouldRegister cycle while resolving slot for "
                "%s — a candidate's ShouldRegister called Get<>() back "
                "into a Base that is itself currently being resolved. "
                "Break the cycle by deferring one of the dependencies "
                "to OnReady.\n", requester_type_name);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    cs.resolving = true;

    Service* winner_svc      = nullptr;
    void*    winner_slot_ptr = nullptr;
    size_t   winner_idx      = 0;

    for (size_t i = 0; i < cs.entries.size(); ++i) {
        auto& e = cs.entries[i];
        if (e.is_fallback) continue;
        if (!e.instance->ShouldRegister()) continue;
        if (winner_svc != nullptr) {
            LOG(Caution, "Two ShouldRegister true for the same Base "
                    "(slot resolved as %s). Both '%s' and '%s' returned "
                    "true. Each Base must have exactly one impl whose "
                    "ShouldRegister returns true for the active device.\n",
                    requester_type_name,
                    typeid(*winner_svc).name(),
                    typeid(*e.instance).name());
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        winner_svc      = e.instance.get();
        winner_slot_ptr = e.slot_ptr;
        winner_idx      = i;
    }

    if (winner_svc == nullptr) {
        for (size_t i = 0; i < cs.entries.size(); ++i) {
            auto& e = cs.entries[i];
            if (!e.is_fallback) continue;
            if (!e.instance->ShouldRegister()) continue;
            if (winner_svc != nullptr) {
                LOG(Caution, "Two fallback ShouldRegister true for the "
                        "same Base (slot resolved as %s). Both '%s' and "
                        "'%s' returned true. Each Base must have at "
                        "most one fallback impl.\n",
                        requester_type_name,
                        typeid(*winner_svc).name(),
                        typeid(*e.instance).name());
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            winner_svc      = e.instance.get();
            winner_slot_ptr = e.slot_ptr;
            winner_idx      = i;
        }
    }

    if (winner_svc) {
        services_[slot] = winner_slot_ptr;
        owned_.push_back(std::move(cs.entries[winner_idx].instance));
    }
    cs.entries.clear();        /* drop losers; release their resources */

    cs.resolving = false;
    cs.resolved  = true;
}

void CerfEmulator::Boot() {
    Bootstrap();
    LOG(Boot, "services up; starting jit...\n");
    Get<JitRunner>().Start();
}

void CerfEmulator::WaitForExit() {
    Get<JitRunner>().Join();
}
