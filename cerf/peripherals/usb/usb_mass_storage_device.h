#pragma once

#include "usb_device.h"
#include "../../storage/disk_image.h"

#include <cstdint>
#include <vector>

class UsbMassStorageDevice : public UsbDevice {
public:
    UsbMassStorageDevice();
    bool OpenImage(const std::string& path, const std::string& name);
    const std::string& ImagePath() const { return image_path_; }
    const std::string& ImageName() const { return image_name_; }
    static constexpr uint32_t kStateKind = 2;
    uint32_t StateKind() const override { return kStateKind; }

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
    void ResetToDefault() override;

protected:
    UsbMassStorageDevice(uint16_t vendor, uint16_t product, uint16_t revision);
    void SetEndpointStalled(uint8_t ep, bool stalled) override;
    /* A transport-specific reader may claim a vendor CDB and provide its IN
       payload. Returning false leaves normal SPC/SBC error handling intact. */
    virtual bool HandleVendorScsiCommand(const uint8_t* cdb, uint8_t cdb_len,
                                         bool data_in, uint32_t transfer_len,
                                         std::vector<uint8_t>& response);

private:
    enum class Phase { AwaitingCbw, DataOut, ReplyReady, ResetRecovery };

    std::vector<uint8_t> BuildDeviceDescriptor() const;
    std::vector<uint8_t> BuildConfigurationDescriptor() const;

    void HandleCbw(const uint8_t* data, uint32_t len);
    void RejectCbw(uint32_t len);
    void ResetTransport();
    void ExecuteScsiCommand();
    void QueueCsw(uint8_t status);
    void SetSense(uint8_t key, uint8_t asc, uint8_t ascq);

    const uint16_t id_vendor_;
    const uint16_t id_product_;
    const uint16_t bcd_device_;
    DiskImage disk_;
    std::string image_path_;
    std::string image_name_;

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
