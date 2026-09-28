#include "board_context.h"

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/fatal.h"
#include "../core/log.h"
#include "../peripherals/cerf_virt/cerf_virt_addr_map.h"

namespace {

constexpr const char* kUnknownBoard = "Unknown / unsupported";

}

bool BoardContext::ShouldRegister() {
    return emu_.Get<DeviceConfig>().board_id == GetBoardId();
}

void BoardContext::OnReady() {
    const std::string_view id = GetBoardId();
    if (id.empty()) {
        LOG(Board, "board: %s\n", kUnknownBoard);
        return;
    }
    auto& db = emu_.Get<BoardDatabase>();
    device_ = db.FindDevice(id);
    if (!device_)
        emu_.Get<Fatal>().Die("board '%.*s' has no devices[] row in db.json",
                              (int)id.size(), id.data());
    soc_    = &db.Soc(device_->soc_id);
    family_ = &db.Family(soc_->family_id);
    LOG(Board, "board: %s (SoC %s)\n", device_->name.c_str(), soc_->name.c_str());
}

std::string_view BoardContext::GetSocId() const {
    return soc_ ? std::string_view(soc_->id) : std::string_view();
}

CpuArch BoardContext::GetCpuArch() const {
    return family_ ? family_->arch : CpuArch::Arm;
}

RomPlacingMode BoardContext::GetRomPlacingMode() const {
    return device_ ? device_->rom_placing_mode : RomPlacingMode::Unknown;
}

const char* BoardContext::BoardName() const {
    return device_ ? device_->name.c_str() : kUnknownBoard;
}

const char* BoardContext::ShortBoardName() const {
    return device_ ? device_->short_name.c_str() : kUnknownBoard;
}

const char* BoardContext::SocName() const {
    return soc_ ? soc_->name.c_str() : "";
}

uint32_t BoardContext::GuestAdditionsWindowSize() const {
    return CerfVirt::kTotalSize;
}

uint32_t BoardContext::ResolveGuestAdditionsColorDepth() const {
    const uint32_t configured =
        emu_.Get<DeviceConfig>().board_configurable_screen_bpp;
    if (configured != 0u) return configured;
    return device_->ga_color_depth;
}
