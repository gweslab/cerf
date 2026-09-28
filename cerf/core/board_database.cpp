#include "board_database.h"

#include "cerf_emulator.h"
#include "cerf_paths.h"
#include "config_json.h"
#include "share_folder_mount_name.h"
#include "string_utils.h"

#include <nlohmann/json.hpp>

REGISTER_SERVICE(BoardDatabase);

namespace {

using nlohmann::json;

constexpr uint32_t kDefaultGaColorDepth = 24u;

const json& RequireArray(const json& root, const char* key, const std::string& path) {
    if (!root.contains(key) || !root[key].is_array())
        CfgFatal(path, std::string("'") + key + "' must be an array");
    return root[key];
}

std::string RequireString(const json& obj, const char* key, const std::string& path,
                          const std::string& ctx) {
    if (!obj.contains(key) || !obj[key].is_string() || obj[key].get<std::string>().empty())
        CfgFatal(path, ctx + "." + key + " must be a non-empty string");
    return obj[key].get<std::string>();
}

bool OptionalBool(const json& obj, const char* key, const std::string& path,
                  const std::string& ctx) {
    if (!obj.contains(key)) return false;
    if (!obj[key].is_boolean()) CfgFatal(path, ctx + "." + key + " must be a boolean");
    return obj[key].get<bool>();
}

uint32_t RequirePositiveInt(const json& obj, const char* key, const std::string& path,
                            const std::string& ctx) {
    if (!obj.contains(key) || !obj[key].is_number_integer() || obj[key].get<int>() < 1)
        CfgFatal(path, ctx + "." + key + " must be a positive integer");
    return (uint32_t)obj[key].get<int>();
}

CpuArch ParseArch(const std::string& v, const std::string& path, const std::string& ctx) {
    if (v == "ARM")  return CpuArch::Arm;
    if (v == "MIPS") return CpuArch::Mips;
    CfgFatal(path, ctx + ".arch '" + v + "' must be ARM or MIPS");
}

RomPlacingMode ParseRomPlacingMode(const std::string& v, const std::string& path,
                                   const std::string& ctx) {
    if (v == "flat_container") return RomPlacingMode::FlatContainer;
    if (v == "imx51_nand")     return RomPlacingMode::Imx51Nand;
    CfgFatal(path, ctx + ".rom_placing_mode '" + v +
                   "' must be flat_container or imx51_nand");
}

}

void BoardDatabase::OnReady() {
    const std::string path = GetCerfDir() + "db.json";
    json root = CfgReadJsonFile(path);
    if (root.is_null()) CfgFatal(path, "is missing: the installation is damaged");

    const char* kMountPointKey = "ga_shared_folder_mount_point";
    if (!root.contains(kMountPointKey) || !root[kMountPointKey].is_string() ||
        !IsValidShareFolderMountName(root[kMountPointKey].get<std::string>()))
        CfgFatal(path, std::string("'") + kMountPointKey +
                       "' must be a valid mount point name");
    ga_shared_folder_mount_point_ = root[kMountPointKey].get<std::string>();

    for (const auto& f : RequireArray(root, "soc_families", path)) {
        if (!f.is_object()) CfgFatal(path, "soc_families[] entries must be objects");
        DbSocFamily row;
        row.id   = RequireString(f, "id", path, "soc_families[]");
        row.name = RequireString(f, "name", path, "soc_families[]");
        row.arch = ParseArch(RequireString(f, "arch", path, "soc_families[]"), path,
                             "soc_families[" + row.id + "]");
        families_.push_back(std::move(row));
    }

    for (const auto& s : RequireArray(root, "socs", path)) {
        if (!s.is_object()) CfgFatal(path, "socs[] entries must be objects");
        DbSoc row;
        row.id        = RequireString(s, "id", path, "socs[]");
        row.name      = RequireString(s, "name", path, "socs[]");
        row.family_id = RequireString(s, "family_id", path, "socs[" + row.id + "]");
        Family(row.family_id);
        socs_.push_back(std::move(row));
    }

    for (const auto& d : RequireArray(root, "devices", path)) {
        if (!d.is_object()) CfgFatal(path, "devices[] entries must be objects");
        DbDevice row;
        row.id = RequireString(d, "id", path, "devices[]");
        const std::string ctx = "devices[" + row.id + "]";
        row.name       = RequireString(d, "name", path, ctx);
        row.short_name = d.contains("short_name")
                             ? RequireString(d, "short_name", path, ctx)
                             : row.name;
        row.supported  = OptionalBool(d, "supported", path, ctx);
        row.soc_id     = RequireString(d, "soc_id", path, ctx);
        Soc(row.soc_id);
        if (d.contains("lcd_panel_size")) {
            const auto& p = d["lcd_panel_size"];
            if (!p.is_object()) CfgFatal(path, ctx + ".lcd_panel_size must be an object");
            row.lcd_panel_size = DbLcdPanelSize{
                RequirePositiveInt(p, "width", path, ctx + ".lcd_panel_size"),
                RequirePositiveInt(p, "height", path, ctx + ".lcd_panel_size") };
        }
        row.ga_color_depth   = d.contains("ga_color_depth")
                                   ? RequirePositiveInt(d, "ga_color_depth", path, ctx)
                                   : kDefaultGaColorDepth;
        row.rom_placing_mode = ParseRomPlacingMode(
            RequireString(d, "rom_placing_mode", path, ctx), path, ctx);
        devices_.push_back(std::move(row));
    }
}

const DbDevice* BoardDatabase::FindDevice(std::string_view id) const {
    for (const auto& d : devices_)
        if (d.id == id) return &d;
    return nullptr;
}

const DbSoc& BoardDatabase::Soc(std::string_view id) const {
    for (const auto& s : socs_)
        if (s.id == id) return s;
    CfgFatal(GetCerfDir() + "db.json", "soc '" + std::string(id) + "' is not in socs[]");
}

const DbSocFamily& BoardDatabase::Family(std::string_view id) const {
    for (const auto& f : families_)
        if (f.id == id) return f;
    CfgFatal(GetCerfDir() + "db.json",
             "soc family '" + std::string(id) + "' is not in soc_families[]");
}
