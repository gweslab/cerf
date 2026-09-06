#include "ford_sync2_media_hub_sd_reader.h"
#include "../../core/log.h"
#include "../../peripherals/usb/usb_state.h"

FordSync2MediaHubSdReader::FordSync2MediaHubSdReader(std::optional<SdCardCid> cid)
    : cid_(cid) {}

void FordSync2MediaHubSdReader::SaveState(StateWriter& w) {
    UsbMassStorageDevice::SaveState(w);
    w.Write<uint8_t>(cid_ ? 1 : 0);
    if (cid_) w.WriteBytes(cid_->data(), cid_->size());
}
void FordSync2MediaHubSdReader::RestoreState(StateReader& r) {
    UsbMassStorageDevice::RestoreState(r);
    uint8_t has = 0; r.Read(has);
    UsbState::Require(r.Ok() && has <= 1, "invalid CID presence");
    cid_.reset();
    if (has) { cid_.emplace(); r.ReadBytes(cid_->data(), cid_->size()); }
    UsbState::Require(r.Ok(), "truncated CID");
}
bool FordSync2MediaHubSdReader::HandleVendorScsiCommand(const uint8_t* cdb, uint8_t cdb_len,
                             bool data_in, uint32_t transfer_len,
                             std::vector<uint8_t>& response) {
    /* Captured from the stock AUTOUSBMSC/Media Hub path: the reader
       requests the raw 16-byte MMC CID through this vendor CDB. */
    if (cdb_len == 6u && data_in && transfer_len == 16u &&
        cdb[0] == 0xCFu && cdb[1] == 0x18u && cdb[2] == 0u &&
        cdb[3] == 0u && cdb[4] == 0x41u && cdb[5] == 0u) {
        if (!cid_) return false;
        response.assign(cid_->begin(), cid_->end());
        return true;
    }

    if (cdb_len != 0u && cdb[0] >= 0xC0u) {
        LOG(Caution, "[MEDIA-HUB] unhandled vendor SCSI CDB len=%u in=%u xfer=%u bytes="
                     "%02X %02X %02X %02X %02X %02X\n",
            static_cast<unsigned>(cdb_len), data_in ? 1u : 0u,
            static_cast<unsigned>(transfer_len), static_cast<unsigned>(cdb[0]),
            static_cast<unsigned>(cdb_len > 1u ? cdb[1] : 0u),
            static_cast<unsigned>(cdb_len > 2u ? cdb[2] : 0u),
            static_cast<unsigned>(cdb_len > 3u ? cdb[3] : 0u),
            static_cast<unsigned>(cdb_len > 4u ? cdb[4] : 0u),
            static_cast<unsigned>(cdb_len > 5u ? cdb[5] : 0u));
    }
    return false;
}
