#pragma once

#include "../../core/sd_card_cid.h"
#include "../../peripherals/usb/usb_mass_storage_device.h"

class FordSync2MediaHubSdReader final : public UsbMassStorageDevice {
public:
    static constexpr uint32_t kStateKind = 3;
    explicit FordSync2MediaHubSdReader(std::optional<SdCardCid> cid = {});
    uint32_t StateKind() const override { return kStateKind; }
    const std::optional<SdCardCid>& Cid() const { return cid_; }
    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

protected:
    bool HandleVendorScsiCommand(const uint8_t* cdb, uint8_t cdb_len,
                                bool data_in, uint32_t transfer_len,
                                std::vector<uint8_t>& response) override;

private:
    std::optional<SdCardCid> cid_;
};
