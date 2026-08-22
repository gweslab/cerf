#include "../board_context.h"

#include "../../boot/guest_cold_boot.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../core/service.h"
#include "../../cpu/emulated_memory.h"

#include <cstdint>

namespace {

/* nk.exe 0x801BB0D4: NKCreateStaticMapping(0x00A01380, 0x1000), arg0 = PA >> 8. */
constexpr uint32_t kArgsPa = 0xA0138000u;

/* nk.exe 0x801BB864 reads args+0x814; dump.bin OEMAddressTable VA 0x80000000 -> PA 0. */
constexpr uint32_t kFlashKernelVaOff = 0x814u;
constexpr uint32_t kFlashKernelVa    = 0x80000000u;

/* nk.exe 0x801BB8EC reads args+0x888; dump.bin PA 0x00080000 partition table, "Config Block" entry 22 at +0x5C0. */
constexpr uint32_t kPartitionTablePaOff = 0x888u;
constexpr uint32_t kPartitionTablePa    = 0x00080000u;

/* nk.exe 0x801BBBCC reads args+0x890 as "DisplayID = %X"; dump.bin ROM offset 0x00082008 = 0x114. */
constexpr uint32_t kDisplayIdOff = 0x890u;
constexpr uint32_t kDisplayId    = 0x114u;

class SymbolMk500BspArgs : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::SymbolMk500;
    }

    void OnReady() override {
        WriteArgs();
        emu_.Get<GuestColdBoot>().RegisterReplay([this] { WriteArgs(); });
    }

private:
    void WriteArgs() {
        auto& mem = emu_.Get<EmulatedMemory>();

        mem.WriteWord(kArgsPa + kFlashKernelVaOff,    kFlashKernelVa);
        mem.WriteWord(kArgsPa + kPartitionTablePaOff, kPartitionTablePa);
        mem.WriteWord(kArgsPa + kDisplayIdOff,        kDisplayId);

        LOG(Board, "SymbolMk500BspArgs: args block at PA 0x%08X; flash kernel VA "
                   "0x%08X, partition table PA 0x%08X, DisplayID 0x%X\n",
            kArgsPa, kFlashKernelVa, kPartitionTablePa, kDisplayId);
    }
};

}

REGISTER_SERVICE(SymbolMk500BspArgs);
