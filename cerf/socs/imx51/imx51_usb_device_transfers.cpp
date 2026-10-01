#include "imx51_usb_device_transfers.h"
#include "usb_device_host.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "imx51_id.h"

#include <cstdint>
#include <vector>

namespace {

/* MCIMX51RM Figure 60-88 / 60-89 (dQH), Figure 60-90 (dTD). */
constexpr uint32_t kDqhStride    = 0x40u;
constexpr uint32_t kDqhOvNext    = 0x08u;
constexpr uint32_t kDqhOvCur     = 0x04u;
constexpr uint32_t kDqhOvToken   = 0x0Cu;
constexpr uint32_t kSetupBufOff  = 0x28u;
constexpr uint32_t kDtdNext      = 0x00u;
constexpr uint32_t kDtdToken     = 0x04u;
constexpr uint32_t kDtdBuf0      = 0x08u;
constexpr uint32_t kDtdTerminate = 1u;
constexpr uint32_t kPageSize     = 0x1000u;

}

REGISTER_SERVICE(Imx51UsbDeviceTransfers);

bool Imx51UsbDeviceTransfers::ShouldRegister() {
    return emu_.Get<BoardContext>().GetSocId() == SocId::Imx51;
}

bool Imx51UsbDeviceTransfers::WriteSetup(uint32_t dqh_base, const uint8_t setup[8]) {
    auto& mem = emu_.Get<EmulatedMemory>();
    if (!dqh_base || !mem.TryTranslate(dqh_base)) {
        LOG(Caution, "Imx51UsbDeviceTransfers: SETUP with invalid ENDPTLISTADDR=0x%08X\n",
            dqh_base);
        return false;
    }
    mem.CopyIn(dqh_base + kSetupBufOff, setup, 8);
    return true;
}

uint32_t Imx51UsbDeviceTransfers::ExecutePrime(uint32_t dqh_base, uint32_t prime_bits) {
    uint32_t done = 0u;
    for (uint32_t ep = 0; ep < 16; ++ep) {
        if ((prime_bits & (1u << ep)) != 0u && ExecuteEndpoint(dqh_base, ep, false)) {
            done |= 1u << ep;
        }
        if ((prime_bits & (1u << (16u + ep))) != 0u && ExecuteEndpoint(dqh_base, ep, true)) {
            done |= 1u << (16u + ep);
        }
    }
    return done;
}

bool Imx51UsbDeviceTransfers::ExecuteEndpoint(uint32_t dqh_base, uint32_t ep, bool dir_in) {
    auto& mem = emu_.Get<EmulatedMemory>();
    if (!dqh_base || !mem.TryTranslate(dqh_base)) {
        LOG(Caution, "Imx51UsbDeviceTransfers: ENDPTPRIME ep%u %s but ENDPTLISTADDR=0x%08X "
            "invalid\n", ep, dir_in ? "IN" : "OUT", dqh_base);
        return false;
    }
    const uint32_t dqh  = dqh_base + (ep * 2u + (dir_in ? 1u : 0u)) * kDqhStride;
    const uint32_t next = mem.ReadWord(dqh + kDqhOvNext);
    if (next & kDtdTerminate) return false;

    uint32_t dtd = next & ~0x1Fu;
    bool any = false;
    for (int guard = 0; guard < 64 && dtd; ++guard) {
        if (!mem.TryTranslate(dtd)) break;
        const uint32_t token = mem.ReadWord(dtd + kDtdToken);
        const uint32_t total = (token >> 16) & 0x7FFFu;

        uint32_t pages[5];
        for (int p = 0; p < 5; ++p) pages[p] = mem.ReadWord(dtd + kDtdBuf0 + p * 4u);

        uint32_t residual = total;
        if (dir_in) {
            std::vector<uint8_t> data(total);
            TransferDtdBuffers(pages, data.data(), total, true);
            if (host_) host_->OnDeviceIn(ep, data.data(), static_cast<uint32_t>(data.size()));
            residual = 0;
        } else {
            std::vector<uint8_t> data(total);
            const uint32_t got = host_ ? host_->OnDeviceOut(ep, data.data(), total) : 0u;
            TransferDtdBuffers(pages, data.data(), got, false);
            residual = total - got;
        }

        const uint32_t new_token = residual << 16;
        mem.WriteWord(dtd + kDtdToken, new_token);
        const uint32_t dtd_next = mem.ReadWord(dtd + kDtdNext);
        mem.WriteWord(dqh + kDqhOvCur, dtd);
        mem.WriteWord(dqh + kDqhOvNext, dtd_next);
        mem.WriteWord(dqh + kDqhOvToken, new_token);
        any = true;
        if (dtd_next & kDtdTerminate) break;
        dtd = dtd_next & ~0x1Fu;
    }
    return any;
}

/* MCIMX51RM Figure 60-90: page 0 bits 11:0 are the Current Offset; the buffer pointer of
   pages 1-4 is bits 31:12. */
void Imx51UsbDeviceTransfers::TransferDtdBuffers(const uint32_t pages[5], uint8_t* host,
                                                 uint32_t n, bool to_host) {
    auto& mem = emu_.Get<EmulatedMemory>();
    uint32_t left = n, cursor = 0;
    for (int p = 0; p < 5 && left; ++p) {
        const uint32_t pa    = (p == 0) ? pages[0] : (pages[p] & ~0xFFFu);
        const uint32_t inpg  = (p == 0) ? (kPageSize - (pages[0] & 0xFFFu)) : kPageSize;
        const uint32_t chunk = inpg < left ? inpg : left;
        if (to_host) mem.CopyOut(pa, host + cursor, chunk);
        else         mem.CopyIn(pa, host + cursor, chunk);
        cursor += chunk;
        left   -= chunk;
    }
}
