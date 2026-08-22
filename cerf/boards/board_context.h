#pragma once

#include "../core/service.h"

#include <cstdint>
#include <optional>
#include <span>
#include <string>

enum class SocFamily {
    Unknown,
    S3C2410,
    SA1110,
    SA1100,
    PXA25x,
    PXA27x,
    OMAP3530,
    Poseidon,
    iMX31,
    iMX32,
    iMX51,
    TegraAPX,
    VR5500,
    VR4102,
    VR4111,
    VR4121,
    VR4122,
    PR31700,
    PR31500,
};

enum class CpuArch { Arm, Mips };

enum class RomPlacingMode { FlatContainer, Imx51Nand, Unknown };

enum class Board {
    Unknown,
    Smdk2410DevEmu,
    OdoArm720,
    OmapEvm3530,
    IpaqGen1,
    ZuneKeel,
    FalconPC3xx,
    Jornada720,
    Jornada820,
    SimpadSl4,
    NecMobilePro900,
    FordSyncGen2,
    SiemensP177,
    SmartBookG138,
    NecRockhopper,
    NecMobilePro700,
    CasioToricomail,
    PhilipsNino300,
    PhilipsVelo1,
    SharpMobilonHc4100,
    CasioCassiopeiaEm500,
    CasioCassiopeiaE55,
    SymbolMk500,
};

/* A board's fixed host-window open size, in guest-surface pixels. */
struct PreferredWindowSize { uint32_t width; uint32_t height; };

struct BoardIdEntry { const char* id; Board board; };

class BoardContext : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    virtual Board          GetBoard()          const = 0;
    virtual SocFamily      GetSoc()             const = 0;
    virtual CpuArch        GetCpuArch()         const = 0;
    virtual RomPlacingMode GetRomPlacingMode()  const = 0;

    /* Cosmetic pre-boot window-size hint for boards with a single fixed LCD.
       Never route actual sizing through this - the real resolution comes
       solely from OnLcdEnabled, and overriding that here would ignore what
       the guest LCD reports. nullopt (base default) = no hint. */
    virtual std::optional<PreferredWindowSize> GetPreferredWindowSize() const {
        return std::nullopt;
    }

    virtual uint32_t GetGuestAdditionsColorDepth() const { return 24u; }

    uint32_t ResolveGuestAdditionsColorDepth() const;

    virtual uint32_t GuestAdditionsWindowBase() const { return 0xF0000000u; }

    static const char* BoardName(Board b);
    static const char* ShortBoardName(Board b);
    static const char* SocFamilyName(SocFamily f);

    static std::span<const BoardIdEntry> BoardIds();
    static Board                         BoardFromId(const std::string& id);
};
