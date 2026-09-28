#pragma once

#include "../core/board_database.h"
#include "../core/service.h"

#include <cstdint>
#include <string_view>

class BoardContext : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    virtual std::string_view GetBoardId() const = 0;

    std::string_view GetSocId()          const;
    CpuArch          GetCpuArch()        const;
    RomPlacingMode   GetRomPlacingMode() const;

    const char* BoardName()      const;
    const char* ShortBoardName() const;
    const char* SocName()        const;

    uint32_t ResolveGuestAdditionsColorDepth() const;

    virtual uint32_t GuestAdditionsWindowBase() const { return 0xF0000000u; }
    virtual uint32_t GuestAdditionsWindowSize() const;

private:
    const DbDevice*    device_ = nullptr;
    const DbSoc*       soc_    = nullptr;
    const DbSocFamily* family_ = nullptr;
};
