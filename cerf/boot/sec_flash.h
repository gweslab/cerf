#pragma once

#include "../core/service.h"
#include "sec_container.h"
#include "../storage/mapped_file.h"

#include <cstddef>
#include <cstdint>

/* Owns the device's `.sec` NAND image (MappedFile + parsed SecContainer), shared
   by the board detector, the NAND BootMode, and the NFC peripheral. Registers
   only when the device dir holds a `.sec`; consumers TryGet and tolerate absence. */
class SecFlash : public Service {
public:
    using Service::Service;
    bool ShouldRegister() override;
    void OnReady() override;

    bool             IsPresent() const { return sec_.IsValid(); }
    const SecHeader& Header()    const { return sec_.Header(); }
    uint64_t FlashSize() const { return sec_.FlashSize(mf_); }

    size_t ReadFlash(uint64_t flash_off, void* dst, size_t len) {
        return sec_.ReadFlash(mf_, flash_off, dst, len);
    }

    /* Raw `.sec` package bytes + size - the payload the SBOOT USB flasher
       downloads, distinct from the de-chunked NAND ReadFlash above. */
    uint64_t FileSize() const { return mf_.Size(); }
    size_t   ReadRaw(uint64_t file_off, void* dst, size_t len) {
        return mf_.Read(file_off, dst, len);
    }

private:
    MappedFile   mf_;
    SecContainer sec_;
};
