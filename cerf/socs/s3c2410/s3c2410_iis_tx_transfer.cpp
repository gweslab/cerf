#include "s3c2410_iis_tx_transfer.h"

#include "s3c2410_iis_regs.h"

#include <cstdint>

/* devemu_wm653 s3c2410x_wavedev.dll sub_7B456BE4: DIDST 0x55000010, DIDSTC |= 3,
   DCON 0xA0900400 (0x7B456C24-0x7B456C3C). */
bool S3C2410IisModelledTxTransfer(const S3C2410DmaAtomicTransfer& t) {
    return t.channels == 0u ||
           (t.channels == 1u && !t.burst && t.bytes == sizeof(uint16_t) &&
            t.dst == S3C2410IisRegs::kBase + S3C2410IisRegs::kOffFifo && t.dst_fixed);
}
