#include "usb_state.h"
#include "usb_mass_storage_device.h"

#include "../../state/state_stream.h"
#include "../../storage/disk_image.h"

#include <cstring>

namespace {

constexpr uint8_t  kMscClass    = 0x08u;
constexpr uint8_t  kMscSubClass = 0x06u;
constexpr uint8_t  kMscProtocol = 0x50u;
constexpr uint16_t kMscIdVendor  = 0x0424u;
constexpr uint16_t kMscIdProduct = 0x4040u;

/* USB Mass Storage Class Bulk-Only Transport Rev. 1.0, Table 5.1 (p13). */
constexpr uint32_t kCbwSignature = 0x43425355u;
constexpr uint32_t kCswSignature = 0x53425355u;
constexpr uint32_t kCbwLength    = 31u;

/* USB Mass Storage Class Bulk-Only Transport Rev. 1.0, Table 5.3 (p14). */
constexpr uint8_t kCswStatusPassed = 0x00u;
constexpr uint8_t kCswStatusFailed = 0x01u;

/* T10 SPC-3 (spc3r23.pdf) 6.4/6.27/6.33; T10 SBC-3 (sbc3r25.pdf) 5.11/5.15/5.32. */
constexpr uint8_t kScsiTestUnitReady   = 0x00u;
constexpr uint8_t kScsiRequestSense    = 0x03u;
constexpr uint8_t kScsiInquiry         = 0x12u;
constexpr uint8_t kScsiReadCapacity10  = 0x25u;
constexpr uint8_t kScsiRead10          = 0x28u;
constexpr uint8_t kScsiWrite10         = 0x2Au;
constexpr uint8_t kScsiModeSense10     = 0x5Au;

/* T10 SPC-3 Table 27 (p41): Sense key descriptions. */
constexpr uint8_t kSenseNoSense    = 0x00u;
constexpr uint8_t kSenseIllegalReq = 0x05u;

uint32_t Be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) | static_cast<uint32_t>(p[3]);
}

uint16_t Be16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

void PutBe32(std::vector<uint8_t>& v, uint32_t x) {
    v.push_back(static_cast<uint8_t>(x >> 24));
    v.push_back(static_cast<uint8_t>(x >> 16));
    v.push_back(static_cast<uint8_t>(x >> 8));
    v.push_back(static_cast<uint8_t>(x));
}

}

bool UsbMassStorageDevice::OpenImage(const std::string& path, const std::string& name) {
    if (disk_.IsOpen() || !disk_.Open(path, 0, false)) return false;
    image_path_ = path;
    image_name_ = name;
    return true;
}

bool UsbMassStorageDevice::HandleVendorScsiCommand(const uint8_t* /*cdb*/,
                                                    uint8_t /*cdb_len*/,
                                                    bool /*data_in*/,
                                                    uint32_t /*transfer_len*/,
                                                    std::vector<uint8_t>& /*response*/) {
    return false;
}

std::vector<uint8_t> UsbMassStorageDevice::BuildDeviceDescriptor() const {
    return {
        18u, kDescDevice,
        0x00u, 0x02u,
        0u, 0u, 0u,
        64u,
        static_cast<uint8_t>(kMscIdVendor & 0xFFu), static_cast<uint8_t>(kMscIdVendor >> 8),
        static_cast<uint8_t>(kMscIdProduct & 0xFFu), static_cast<uint8_t>(kMscIdProduct >> 8),
        0u, 0u,
        0u, 0u, 0u,
        1u,
    };
}

std::vector<uint8_t> UsbMassStorageDevice::BuildConfigurationDescriptor() const {
    return {
        9u, kDescConfiguration, 32u, 0u, 1u, 1u, 0u, 0xC0u, 0u,
        9u, 4u, 0u, 0u, 2u, kMscClass, kMscSubClass, kMscProtocol, 0u,
        7u, 5u, 0x81u, 0x02u, 64u, 0u, 0u,
        7u, 5u, 0x02u, 0x02u, 64u, 0u, 0u,
    };
}

bool UsbMassStorageDevice::GetDescriptor(uint8_t type, uint8_t /*index*/, uint16_t /*lang_id*/,
                                         std::vector<uint8_t>& out) {
    if (type == kDescDevice) {
        out = BuildDeviceDescriptor();
        return true;
    }
    if (type == kDescConfiguration) {
        out = BuildConfigurationDescriptor();
        return true;
    }
    return false;
}

bool UsbMassStorageDevice::HandleClassRequest(const SetupPacket& setup,
                                              std::vector<uint8_t>& data_stage) {
    if (setup.bRequest == kBotReqGetMaxLun) {
        data_stage = {0u};
        return true;
    }
    if (setup.bRequest == kBotReqReset) {
        phase_ = Phase::AwaitingCbw;
        pending_in_.clear();
        pending_in_off_ = 0u;
        return true;
    }
    return false;
}

void UsbMassStorageDevice::SetSense(uint8_t key, uint8_t asc, uint8_t ascq) {
    sense_key_ = key;
    sense_asc_ = asc;
    sense_ascq_ = ascq;
}

void UsbMassStorageDevice::QueueCsw(uint8_t status) {
    const uint32_t transferred = cbw_dir_in_
        ? static_cast<uint32_t>(pending_in_.size())
        : static_cast<uint32_t>(out_buf_.size());
    const uint32_t residue = transferred >= cbw_data_len_ ? 0u : cbw_data_len_ - transferred;
    pending_in_.push_back(static_cast<uint8_t>(kCswSignature & 0xFFu));
    pending_in_.push_back(static_cast<uint8_t>((kCswSignature >> 8) & 0xFFu));
    pending_in_.push_back(static_cast<uint8_t>((kCswSignature >> 16) & 0xFFu));
    pending_in_.push_back(static_cast<uint8_t>((kCswSignature >> 24) & 0xFFu));
    pending_in_.push_back(static_cast<uint8_t>(cbw_tag_ & 0xFFu));
    pending_in_.push_back(static_cast<uint8_t>((cbw_tag_ >> 8) & 0xFFu));
    pending_in_.push_back(static_cast<uint8_t>((cbw_tag_ >> 16) & 0xFFu));
    pending_in_.push_back(static_cast<uint8_t>((cbw_tag_ >> 24) & 0xFFu));
    pending_in_.push_back(static_cast<uint8_t>(residue & 0xFFu));
    pending_in_.push_back(static_cast<uint8_t>((residue >> 8) & 0xFFu));
    pending_in_.push_back(static_cast<uint8_t>((residue >> 16) & 0xFFu));
    pending_in_.push_back(static_cast<uint8_t>((residue >> 24) & 0xFFu));
    pending_in_.push_back(status);
    phase_ = Phase::ReplyReady;
}

void UsbMassStorageDevice::ExecuteScsiCommand() {
    const uint8_t op = cbwcb_[0];

    if (op == kScsiTestUnitReady) {
        SetSense(kSenseNoSense, 0u, 0u);
        cbw_data_len_ = 0u;
        QueueCsw(kCswStatusPassed);
        return;
    }

    if (op == kScsiInquiry) {
        std::vector<uint8_t> d(36u, 0u);
        d[0] = 0x00u;
        d[2] = 0x04u;
        d[3] = 0x02u;
        d[4] = 31u;
        std::memcpy(&d[8], "CERF    ", 8);
        std::memcpy(&d[16], "SD Card Reader  ", 16);
        std::memcpy(&d[32], "1.0 ", 4);
        pending_in_.insert(pending_in_.end(), d.begin(), d.end());
        SetSense(kSenseNoSense, 0u, 0u);
        QueueCsw(kCswStatusPassed);
        return;
    }

    if (op == kScsiReadCapacity10) {
        const uint64_t sectors = disk_.SectorCount();
        const uint32_t last_lba = sectors == 0u ? 0u
            : static_cast<uint32_t>(sectors > 0xFFFFFFFFull ? 0xFFFFFFFFu : sectors - 1u);
        std::vector<uint8_t> d;
        PutBe32(d, last_lba);
        PutBe32(d, DiskImage::kSectorSize);
        pending_in_.insert(pending_in_.end(), d.begin(), d.end());
        SetSense(kSenseNoSense, 0u, 0u);
        QueueCsw(kCswStatusPassed);
        return;
    }

    if (op == kScsiModeSense10) {
        /* T10 SPC-3 (spc3r23.pdf) Table 240 (p280): Mode parameter header(10),
           zero block descriptors, no mode pages. */
        std::vector<uint8_t> d(8u, 0u);
        d[1] = 6u;
        pending_in_.insert(pending_in_.end(), d.begin(), d.end());
        SetSense(kSenseNoSense, 0u, 0u);
        QueueCsw(kCswStatusPassed);
        return;
    }

    if (op == kScsiRead10) {
        const uint32_t lba = Be32(&cbwcb_[2]);
        const uint32_t blocks = Be16(&cbwcb_[7]);
        std::vector<uint8_t> d(static_cast<size_t>(blocks) * DiskImage::kSectorSize, 0u);
        if (blocks == 0u || !disk_.ReadSectors(lba, blocks, d.data())) {
            SetSense(kSenseIllegalReq, 0x21u, 0x00u);
            QueueCsw(kCswStatusFailed);
            return;
        }
        pending_in_.insert(pending_in_.end(), d.begin(), d.end());
        SetSense(kSenseNoSense, 0u, 0u);
        QueueCsw(kCswStatusPassed);
        return;
    }

    if (op == kScsiWrite10) {
        const uint32_t lba = Be32(&cbwcb_[2]);
        const uint32_t blocks = Be16(&cbwcb_[7]);
        const bool ok = blocks != 0u &&
            out_buf_.size() >= static_cast<size_t>(blocks) * DiskImage::kSectorSize &&
            disk_.WriteSectors(lba, blocks, out_buf_.data());
        SetSense(ok ? kSenseNoSense : kSenseIllegalReq, ok ? 0u : 0x21u, 0u);
        QueueCsw(ok ? kCswStatusPassed : kCswStatusFailed);
        return;
    }

    if (op == kScsiRequestSense) {
        std::vector<uint8_t> d(18u, 0u);
        d[0] = 0x70u;
        d[2] = sense_key_;
        d[7] = 10u;
        d[12] = sense_asc_;
        d[13] = sense_ascq_;
        pending_in_.insert(pending_in_.end(), d.begin(), d.end());
        QueueCsw(kCswStatusPassed);
        return;
    }

    std::vector<uint8_t> vendor_response;
    if (HandleVendorScsiCommand(cbwcb_, cbwcb_len_, cbw_dir_in_, cbw_data_len_,
                                vendor_response)) {
        pending_in_.insert(pending_in_.end(), vendor_response.begin(), vendor_response.end());
        SetSense(kSenseNoSense, 0u, 0u);
        QueueCsw(kCswStatusPassed);
        return;
    }

    SetSense(kSenseIllegalReq, 0x20u, 0x00u);
    QueueCsw(kCswStatusFailed);
}

void UsbMassStorageDevice::HandleCbw(const uint8_t* data, uint32_t len) {
    if (len != kCbwLength) return;
    const uint32_t signature = data[0] | (static_cast<uint32_t>(data[1]) << 8) |
        (static_cast<uint32_t>(data[2]) << 16) | (static_cast<uint32_t>(data[3]) << 24);
    if (signature != kCbwSignature || data[13] != 0u ||
        (data[12] & 0x7Fu) != 0u || data[14] == 0u || data[14] > 16u) {
        return;
    }
    cbw_tag_      = data[4] | (data[5] << 8) | (data[6] << 16) | (data[7] << 24);
    cbw_data_len_ = data[8] | (data[9] << 8) | (data[10] << 16) | (data[11] << 24);
    cbw_dir_in_   = (data[12] & 0x80u) != 0u;
    cbwcb_len_    = static_cast<uint8_t>(data[14] & 0x1Fu);
    std::memcpy(cbwcb_, &data[15], 16u);

    pending_in_.clear();
    pending_in_off_ = 0u;

    out_buf_.clear();
    const uint8_t op = cbwcb_[0];
    const uint8_t required = (op == kScsiRead10 || op == kScsiWrite10 ||
        op == kScsiReadCapacity10 || op == kScsiModeSense10) ? 10u : 6u;
    const uint32_t write_bytes = static_cast<uint32_t>(Be16(&cbwcb_[7])) * DiskImage::kSectorSize;
    if (cbwcb_len_ < required ||
        (op == kScsiWrite10 && (cbw_dir_in_ || cbw_data_len_ != write_bytes)) ||
        (cbw_data_len_ > 0u && !cbw_dir_in_ && op != kScsiWrite10)) {
        SetSense(kSenseIllegalReq, 0x24u, 0u);
        QueueCsw(kCswStatusFailed);
        return;
    }
    if (cbw_data_len_ > 0u && !cbw_dir_in_) {
        out_buf_.reserve(cbw_data_len_);
        phase_ = Phase::DataOut;
        return;
    }
    ExecuteScsiCommand();
}

void UsbMassStorageDevice::OnBulkOut(uint8_t /*ep*/, const uint8_t* data, uint32_t len) {
    if (phase_ == Phase::AwaitingCbw) {
        HandleCbw(data, len);
        return;
    }
    if (phase_ == Phase::DataOut) {
        if (len > cbw_data_len_ - out_buf_.size()) {
            SetSense(kSenseIllegalReq, 0x24u, 0u);
            QueueCsw(kCswStatusFailed);
            return;
        }
        out_buf_.insert(out_buf_.end(), data, data + len);
        if (out_buf_.size() >= cbw_data_len_) {
            ExecuteScsiCommand();
        }
    }
}

uint32_t UsbMassStorageDevice::OnBulkIn(uint8_t /*ep*/, uint8_t* dst, uint32_t max) {
    if (pending_in_off_ >= pending_in_.size()) {
        if (phase_ == Phase::ReplyReady) {
            phase_ = Phase::AwaitingCbw;
            pending_in_.clear();
            pending_in_off_ = 0u;
        }
        return 0u;
    }
    const uint32_t remain = static_cast<uint32_t>(pending_in_.size() - pending_in_off_);
    const uint32_t n = remain < max ? remain : max;
    std::memcpy(dst, pending_in_.data() + pending_in_off_, n);
    pending_in_off_ += n;
    /* USB Mass Storage Class BOT Rev. 1.0, 5.1 (p6): next CBW may follow
       this CSW with no intervening IN poll - flip phase here, not lazily. */
    if (phase_ == Phase::ReplyReady && pending_in_off_ >= pending_in_.size()) {
        phase_ = Phase::AwaitingCbw;
        pending_in_.clear();
        pending_in_off_ = 0u;
    }
    return n;
}

void UsbMassStorageDevice::SaveState(StateWriter& w) {
    UsbDevice::SaveState(w);
    UsbState::WriteString(w, image_path_);
    UsbState::WriteString(w, image_name_);
    w.Write(phase_);
    w.Write(cbw_tag_);
    w.Write(cbw_data_len_);
    w.Write<uint8_t>(cbw_dir_in_ ? 1 : 0);
    w.WriteBytes(cbwcb_, sizeof(cbwcb_));
    w.Write(cbwcb_len_);
    w.Write(sense_key_);
    w.Write(sense_asc_);
    w.Write(sense_ascq_);
    UsbState::WriteBuffer(w, pending_in_);
    w.Write<uint32_t>(static_cast<uint32_t>(pending_in_off_));
    UsbState::WriteBuffer(w, out_buf_);
}

void UsbMassStorageDevice::RestoreState(StateReader& r) {
    UsbDevice::RestoreState(r);
    const auto path = UsbState::ReadString(r);
    const auto name = UsbState::ReadString(r);
    if (!OpenImage(path, name)) {
        LOG(Caution, "USB restore: cannot open saved image '%s'\n", path.c_str());
        UsbState::Require(false, "saved media is missing or cannot be opened");
    }
    r.Read(phase_);
    r.Read(cbw_tag_);
    r.Read(cbw_data_len_);
    uint8_t direction = 0; r.Read(direction); cbw_dir_in_ = direction != 0;
    UsbState::Require(r.Ok() && direction <= 1, "invalid transfer direction");
    r.ReadBytes(cbwcb_, sizeof(cbwcb_));
    r.Read(cbwcb_len_);
    r.Read(sense_key_);
    r.Read(sense_asc_);
    r.Read(sense_ascq_);
    constexpr uint32_t max_write = 65535u * DiskImage::kSectorSize;
    UsbState::ReadBuffer(r, pending_in_, max_write + 13u);
    uint32_t offset = 0; r.Read(offset); pending_in_off_ = offset;
    UsbState::ReadBuffer(r, out_buf_, max_write);
    UsbState::Require(r.Ok() && cbwcb_len_ <= 16 && offset <= pending_in_.size() &&
        (phase_ == Phase::AwaitingCbw || phase_ == Phase::DataOut || phase_ == Phase::ReplyReady),
        "invalid mass storage phase");
    if (phase_ == Phase::DataOut) {
        const uint32_t expected = static_cast<uint32_t>(Be16(&cbwcb_[7])) * DiskImage::kSectorSize;
        UsbState::Require(cbwcb_len_ >= 10 && cbwcb_[0] == kScsiWrite10 &&
            !cbw_dir_in_ && cbw_data_len_ == expected && out_buf_.size() <= expected,
            "invalid partial write");
    }
}
