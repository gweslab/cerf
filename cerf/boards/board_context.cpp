#include "board_context.h"

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/log.h"

namespace {

constexpr BoardIdEntry kBoardIds[] = {
    {"devemu",            Board::Smdk2410DevEmu},
    {"odo",               Board::OdoArm720},
    {"omap_3530_evm",     Board::OmapEvm3530},
    {"ipaq_gen1",         Board::IpaqGen1},
    {"zune_30",           Board::ZuneKeel},
    {"falcon_4220",       Board::FalconPC3xx},
    {"jornada_720",       Board::Jornada720},
    {"jornada_820",       Board::Jornada820},
    {"simpad_sl4",        Board::SimpadSl4},
    {"nec_mobilepro_900", Board::NecMobilePro900},
    {"ford_sync_2",       Board::FordSyncGen2},
    {"siemens_p177",      Board::SiemensP177},
    {"smartbook_g138",    Board::SmartBookG138},
    {"nec_rockhopper",    Board::NecRockhopper},
    {"nec_mobilepro_700", Board::NecMobilePro700},
    {"casio_toricomail",  Board::CasioToricomail},
    {"philips_nino_300",  Board::PhilipsNino300},
    {"philips_velo_1",    Board::PhilipsVelo1},
    {"sharp_mobilon_hc4100", Board::SharpMobilonHc4100},
    {"casio_cassiopeia_em500", Board::CasioCassiopeiaEm500},
    {"casio_cassiopeia_e55", Board::CasioCassiopeiaE55},
    {"symbol_mk500",      Board::SymbolMk500},
};

}  /* namespace */

bool BoardContext::ShouldRegister() {
    return BoardFromId(emu_.Get<DeviceConfig>().board_id) == GetBoard();
}

void BoardContext::OnReady() {
    LOG(Board, "board: %s (SoC %s)\n", BoardName(GetBoard()), SocFamilyName(GetSoc()));
}

std::span<const BoardIdEntry> BoardContext::BoardIds() {
    return std::span<const BoardIdEntry>(kBoardIds);
}

Board BoardContext::BoardFromId(const std::string& id) {
    if (id.empty()) return Board::Unknown;
    for (const auto& e : kBoardIds) {
        if (id == e.id) return e.board;
    }
    return Board::Unknown;
}

const char* BoardContext::BoardName(Board b) {
    switch (b) {
        case Board::Unknown:          return "Unknown / unsupported";
        case Board::Smdk2410DevEmu:   return "Microsoft Device Emulator (SMDK2410)";
        case Board::OdoArm720:        return "Microsoft CE Hardware Reference Platform (Odo)";
        case Board::OmapEvm3530:      return "TI OMAP 3530 EVM";
        case Board::IpaqGen1:         return "Compaq iPAQ (1st gen)";
        case Board::ZuneKeel:         return "Microsoft Zune 30";
        case Board::FalconPC3xx:      return "Datalogic Falcon 4220";
        case Board::Jornada720:       return "HP Jornada 720";
        case Board::Jornada820:       return "HP Jornada 820";
        case Board::SimpadSl4:        return "Siemens SIMpad SL4";
        case Board::NecMobilePro900:  return "NEC MobilePro 900";
        case Board::FordSyncGen2:     return "Ford SYNC 2";
        case Board::SiemensP177:      return "Siemens SIMATIC TP177B 4\"";
        case Board::SmartBookG138:    return "SmartBook G138";
        case Board::NecRockhopper:    return "NEC Rockhopper (DDB-VR5500A)";
        case Board::NecMobilePro700:  return "NEC MobilePro 700";
        case Board::CasioToricomail:  return "Casio Toricomail";
        case Board::PhilipsNino300:   return "Philips Nino 300";
        case Board::PhilipsVelo1:     return "Philips Velo 1";
        case Board::SharpMobilonHc4100: return "Sharp Mobilon HC-4100";
        case Board::CasioCassiopeiaEm500: return "Casio Cassiopeia EM-500";
        case Board::CasioCassiopeiaE55:   return "Casio Cassiopeia E-55";
        case Board::SymbolMk500:      return "Symbol MK500";
    }
    return "Unknown / unsupported";
}

const char* BoardContext::ShortBoardName(Board b) {
    switch (b) {
        case Board::Unknown:          return "Unknown / unsupported";
        case Board::Smdk2410DevEmu:   return "Device Emulator";
        case Board::OdoArm720:        return "Reference Platform";
        case Board::OmapEvm3530:      return "OMAP3530 EVM";
        case Board::IpaqGen1:         return "iPAQ";
        case Board::ZuneKeel:         return "Zune 30";
        case Board::FalconPC3xx:      return "Falcon 4220";
        case Board::Jornada720:       return "Jornada 720";
        case Board::Jornada820:       return "Jornada 820";
        case Board::SimpadSl4:        return "SIMpad SL4";
        case Board::NecMobilePro900:  return "MobilePro 900";
        case Board::FordSyncGen2:     return "Ford SYNC 2";
        case Board::SiemensP177:      return "SIMATIC TP177B";
        case Board::SmartBookG138:    return "SmartBook G138";
        case Board::NecRockhopper:    return "Rockhopper";
        case Board::NecMobilePro700:  return "MobilePro 700";
        case Board::CasioToricomail:  return "Toricomail";
        case Board::PhilipsNino300:   return "Nino 300";
        case Board::PhilipsVelo1:     return "Velo 1";
        case Board::SharpMobilonHc4100: return "Mobilon HC-4100";
        case Board::CasioCassiopeiaEm500: return "EM-500";
        case Board::CasioCassiopeiaE55:   return "E-55";
        case Board::SymbolMk500:      return "MK500";
    }
    return "Unknown / unsupported";
}

const char* BoardContext::SocFamilyName(SocFamily f) {
    switch (f) {
        case SocFamily::Unknown:   return "Unknown";
        case SocFamily::S3C2410:   return "S3C2410";
        case SocFamily::SA1110:    return "SA1110";
        case SocFamily::SA1100:    return "SA1100";
        case SocFamily::PXA25x:    return "PXA25x";
        case SocFamily::PXA27x:    return "PXA27x";
        case SocFamily::OMAP3530:  return "OMAP3530";
        case SocFamily::Poseidon:  return "Poseidon";
        case SocFamily::iMX31:     return "iMX31";
        case SocFamily::iMX32:     return "iMX32";
        case SocFamily::iMX51:     return "iMX51";
        case SocFamily::TegraAPX:  return "TegraAPX";
        case SocFamily::VR5500:    return "VR5500";
        case SocFamily::VR4102:    return "VR4102";
        case SocFamily::VR4111:    return "VR4111";
        case SocFamily::VR4121:    return "VR4121";
        case SocFamily::VR4122:    return "VR4122";
        case SocFamily::PR31700:   return "PR31700";
        case SocFamily::PR31500:   return "PR31500";
    }
    return "Unknown";
}

uint32_t BoardContext::ResolveGuestAdditionsColorDepth() const {
    const uint32_t configured =
        emu_.Get<DeviceConfig>().board_configurable_screen_bpp;
    if (configured != 0u) return configured;
    return GetGuestAdditionsColorDepth();
}
