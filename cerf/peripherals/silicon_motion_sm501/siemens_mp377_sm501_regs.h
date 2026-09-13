#pragma once

#include "siemens_mp377_sm501.h"

#include "../../peripherals/peripheral_base.h"
#include "../../state/state_stream.h"

#include <cstddef>
#include <cstdint>
#include <mutex>
#include <vector>

namespace siemens_mp377 {

class SiemensMp377Sm501Ac97;
class SiemensMp377Sm501AudioMcu;
class SiemensMp377Sm501AudioOutput;
class SiemensMp377Sm501Dma;
class SiemensMp377Sm501PowerGpio;

class SiemensMp377Sm501Regs : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override;
    uint32_t MmioSize() const override;

    uint32_t PanelFbOffset() const;
    uint32_t PanelPitchBytes() const;
    uint32_t PanelWidthPixels() const;
    uint32_t PanelHeightLines() const;
    uint32_t CrtFbOffset() const;
    uint32_t CrtPitchBytes() const;
    uint32_t CrtWidthPixels() const;
    uint32_t CrtHeightLines() const;
    uint32_t ReadSm501Register(uint32_t offset) const;

    uint8_t ReadByte(uint32_t address) override;
    uint16_t ReadHalf(uint32_t address) override;
    uint32_t ReadWord(uint32_t address) override;
    void WriteByte(uint32_t address, uint8_t value) override;
    void WriteHalf(uint32_t address, uint16_t value) override;
    void WriteWord(uint32_t address, uint32_t value) override;

    void SaveState(StateWriter& writer) override;
    void RestoreState(StateReader& reader) override;
    void PostRestore() override;

private:
    friend class SiemensMp377Sm501Dma;
    friend class SiemensMp377Sm501Ac97;
    friend class SiemensMp377Sm501AudioOutput;
    friend class SiemensMp377Sm501AudioMcu;
    friend class SiemensMp377Sm501PowerGpio;

    static uint32_t NormalizePanelFbOffset(uint32_t value);
    void ResetDevice(bool synchronize_audio);
    static uint32_t DecodePanelPitchBytes(uint32_t value);
    void WriteResolvedWord(uint32_t address, uint32_t offset, uint32_t value);

    /* SM501 Databook v1.02, Interrupt Mask/Status; SSP0 status and cascade are
       owned by SiemensMp377SmiBridge. */
    static constexpr uint32_t kSm501WritableIrqMaskBits = 0x00120500u;
    static constexpr uint32_t kSm501LatchedIrqBits = 0x00120400u;
    uint32_t Sm501LatchedInterruptStatus() const;
    uint32_t Sm501InterruptMask() const;
    void SetSm501InterruptMask(uint32_t value);
    void RefreshSm501InterruptLine();
    void RaiseSm501InterruptBits(uint32_t bits);
    void ClearSm501InterruptBits(uint32_t bits);
    uint32_t SspInterruptStatus(uint32_t base) const;
    void RefreshSspInterruptCascade();

    std::vector<uint32_t> regs_;
    uint32_t panel_fb_raw_ = 0u;
    uint32_t panel_pitch_bytes_ = 0u;
    mutable std::mutex sm501_irq_mutex_;
};

} // namespace siemens_mp377
