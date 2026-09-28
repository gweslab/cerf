#pragma once

#include "service.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

enum class CpuArch { Arm, Mips };

enum class RomPlacingMode { FlatContainer, Imx51Nand, Unknown };

struct DbLcdPanelSize { uint32_t width; uint32_t height; };

struct DbSocFamily {
    std::string id;
    std::string name;
    CpuArch     arch;
};

struct DbSoc {
    std::string id;
    std::string name;
    std::string family_id;
};

struct DbDevice {
    std::string                   id;
    std::string                   name;
    std::string                   short_name;
    bool                          supported;
    std::string                   soc_id;
    std::optional<DbLcdPanelSize> lcd_panel_size;
    uint32_t                      ga_color_depth;
    RomPlacingMode                rom_placing_mode;
};

class BoardDatabase : public Service {
public:
    using Service::Service;

    void OnReady() override;

    std::span<const DbDevice> Devices() const { return devices_; }

    const DbDevice*    FindDevice(std::string_view id) const;
    const DbSoc&       Soc(std::string_view id) const;
    const DbSocFamily& Family(std::string_view id) const;

private:
    std::vector<DbSocFamily> families_;
    std::vector<DbSoc>       socs_;
    std::vector<DbDevice>    devices_;
};
