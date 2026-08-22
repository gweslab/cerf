#pragma once

#include "usb_device.h"

#include <cstdint>
#include <vector>

class DiskImage;

class UsbMassStorageDevice : public UsbDevice {
public:
    explicit UsbMassStorageDevice(DiskImage& disk);

    /* USB Mass Storage Class Bulk-Only Transport Rev. 1.0, 3.1/3.2 (p6-7). */
    static constexpr uint8_t kBotReqReset     = 0xFFu;
    static constexpr uint8_t kBotReqGetMaxLun = 0xFEu;

    bool GetDescriptor(uint8_t type, uint8_t index, uint16_t lang_id,
                       std::vector<uint8_t>& out) override;
    bool HandleClassRequest(const SetupPacket& setup,
                            std::vector<uint8_t>& data_stage) override;
    void     OnBulkOut(uint8_t ep, const uint8_t* data, uint32_t len) override;
    uint32_t OnBulkIn(uint8_t ep, uint8_t* dst, uint32_t max) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    enum class Phase { AwaitingCbw, DataOut, ReplyReady };

    std::vector<uint8_t> BuildDeviceDescriptor() const;
    std::vector<uint8_t> BuildConfigurationDescriptor() const;

    void HandleCbw(const uint8_t* data, uint32_t len);
    void ExecuteScsiCommand();
    void QueueCsw(uint8_t status);
    void SetSense(uint8_t key, uint8_t asc, uint8_t ascq);

    DiskImage& disk_;

    Phase    phase_          = Phase::AwaitingCbw;
    uint32_t cbw_tag_        = 0u;
    uint32_t cbw_data_len_   = 0u;
    bool     cbw_dir_in_     = false;
    uint8_t  cbwcb_[16]      = {};
    uint8_t  cbwcb_len_      = 0u;
    std::vector<uint8_t> out_buf_;

    std::vector<uint8_t> pending_in_;
    size_t                pending_in_off_ = 0u;

    uint8_t sense_key_  = 0u;
    uint8_t sense_asc_  = 0u;
    uint8_t sense_ascq_ = 0u;
};
