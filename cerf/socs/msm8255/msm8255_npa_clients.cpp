#include "msm8255_npa_clients.h"

#include "msm8255_rpcrouter_wire.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/emulated_memory.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

bool Msm8255NpaClients::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Msm8255;
}

void Msm8255NpaClients::OnReady() {
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        resource_.clear();
        request_.clear();
        issued_.clear();
    });
}

uint32_t Msm8255NpaClients::ResourceKeyAt(uint32_t body, uint32_t off) {
    auto& mem = emu_.Get<EmulatedMemory>();

    const uint32_t length = Be32(mem.ReadWord(body + off));

    uint32_t key  = length;
    uint32_t at   = off + 4u;
    uint32_t left = length;
    for (; left >= 4u; left -= 4u, at += 4u) {
        key = key * 31u + Be32(mem.ReadWord(body + at));
    }
    if (left != 0u) {
        const uint32_t named = 0xFFFFFFFFu << (8u * (4u - left));
        key = key * 31u + (Be32(mem.ReadWord(body + at)) & named);
    }
    return key;
}

uint32_t Msm8255NpaClients::IssueHandle(uint32_t resource) {
    resource_.push_back(resource);
    request_.push_back(0u);
    issued_.push_back(0u);
    return static_cast<uint32_t>(resource_.size());
}

uint32_t Msm8255NpaClients::HandleCount() const {
    return static_cast<uint32_t>(resource_.size());
}

uint32_t Msm8255NpaClients::ApplyRequest(uint32_t handle, uint32_t request) {
    const uint32_t self = handle - 1u;
    request_[self] = request;
    issued_[self]  = 1u;

    for (uint32_t i = 0; i < resource_.size(); ++i) {
        if (i == self || resource_[i] != resource_[self] || issued_[i] == 0u) {
            continue;
        }
        emu_.Get<Fatal>().Die(
            "msm8255 npa clients: client handle %u requests %u of the resource "
            "client handle %u already requested %u of, and the rule this peer "
            "would aggregate them by is not modeled",
            handle, request, i + 1u, request_[i]);
    }
    return request;
}

void Msm8255NpaClients::SaveState(StateWriter& w) {
    w.Write<uint32_t>("resource_count", static_cast<uint32_t>(resource_.size()));
    for (uint32_t i = 0; i < resource_.size(); ++i) {
        w.Write<uint32_t>("resource", resource_[i]);
        w.Write<uint32_t>("request", request_[i]);
        w.Write<uint32_t>("issued", issued_[i]);
    }
}

void Msm8255NpaClients::RestoreState(StateReader& r) {
    uint32_t clients = 0;
    r.Read("resource_count", clients);
    resource_.assign(clients, 0u);
    request_.assign(clients, 0u);
    issued_.assign(clients, 0u);
    for (uint32_t i = 0; i < clients; ++i) {
        r.Read("resource", resource_[i]);
        r.Read("request", request_[i]);
        r.Read("issued", issued_[i]);
    }
}

REGISTER_SERVICE(Msm8255NpaClients);
