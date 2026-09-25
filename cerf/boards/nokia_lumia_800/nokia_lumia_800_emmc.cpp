#include "../../peripherals/sk_hynix_h26m52002ckr/sk_hynix_h26m52002ckr.h"

#include "../../boot/rom_parser_service.h"
#include "../../boot/rom_wmstore_parse.h"
#include "../../core/cerf_emulator.h"
#include "../../core/cerf_paths.h"
#include "../../core/device_config.h"
#include "../../core/fatal.h"
#include "../../core/host_file_bytes.h"
#include "../../core/log.h"
#include "../board_context.h"
#include "nokia_lumia_800_id.h"

#include <algorithm>
#include <cstring>

namespace {

namespace ri = cerf::rom_image_parse;

constexpr uint32_t kEmmcSlotIndex = 0u;

constexpr uint8_t  kUnshippedSectorFill   = 0x00u;
constexpr uint64_t kFlasherEraseUnit      = 0x800000u;
constexpr uint8_t  kFlasherWriteEraseFill = 0xFFu;

constexpr uint32_t kMbrEntryTypeOff    = 450u;
constexpr uint32_t kMbrEntryLbaOff     = 454u;
constexpr uint32_t kMbrSignatureOff    = 510u;
constexpr uint8_t  kMbrSignature0      = 0x55u;
constexpr uint8_t  kMbrSignature1      = 0xAAu;
constexpr uint8_t  kPartitionExtended  = 0x05u;
constexpr uint8_t  kPartitionStore     = 0x48u;
constexpr uint32_t kEbrStoreRelativeLba = 1u;
constexpr uint32_t kMinStoreContainerOrigin = 2u;

void PutLe32(uint8_t* at, uint32_t value) {
    for (uint32_t i = 0; i < 4u; ++i) at[i] = static_cast<uint8_t>(value >> (8u * i));
}

class NokiaLumia800Emmc : public SkHynixH26m52002ckr {
public:
    using SkHynixH26m52002ckr::SkHynixH26m52002ckr;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NokiaLumia800;
    }

    uint32_t SlotIndex() const override { return kEmmcSlotIndex; }

    void OnReady() override {
        LoadImageOrigin();
        SkHynixH26m52002ckr::OnReady();
        LoadUserAreaErase();
    }

protected:
    void ReadBlock(uint32_t sector, uint8_t* out) override {
        if (sector < image_origin_) {
            ReadStoreContainerSector(sector, out);
            return;
        }
        const ParsedRom& rom = emu_.Get<RomParserService>().Primary();
        const uint64_t rel = uint64_t(sector - image_origin_) * cerf_mmc::kBlockBytes;
        if (rel + cerf_mmc::kBlockBytes <= rom.wmstore_payload_bytes) {
            std::memcpy(out, rom.raw.data() + rom.wmstore_payload_off + size_t(rel),
                        cerf_mmc::kBlockBytes);
            return;
        }
        if (rel < rom.wmstore_payload_bytes) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: sector %u straddles the end of the %zu "
                "payload bytes of %s", kEmmcSlotIndex, sector,
                rom.wmstore_payload_bytes, rom.filename.c_str());
        }
        std::memset(out, UnshippedByte(sector), cerf_mmc::kBlockBytes);
    }

private:
    const ParsedRom& PackagePrimary() {
        const RomParserService& parser = emu_.Get<RomParserService>();
        if (!parser.Ok() || !parser.Primary().is_wmstore) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: the loaded firmware package is not a "
                "_wmstore container, so no sector content is modeled",
                kEmmcSlotIndex);
        }
        return parser.Primary();
    }

    void LoadImageOrigin() {
        const ParsedRom& rom = PackagePrimary();
        ri::EscoRange image;
        if (!ri::EscoImageRange(rom.raw, image)) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: %s carries no image write record, so its "
                "place on the card is not known", kEmmcSlotIndex,
                rom.filename.c_str());
        }
        if (image.start % cerf_mmc::kBlockBytes != 0u) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: %s is written at card byte 0x%llX, which "
                "is not a whole sector", kEmmcSlotIndex, rom.filename.c_str(),
                static_cast<unsigned long long>(image.start));
        }
        const uint64_t origin = image.start / cerf_mmc::kBlockBytes;
        const uint64_t payload_sectors =
            (uint64_t(rom.wmstore_payload_bytes) + cerf_mmc::kBlockBytes - 1u) /
            cerf_mmc::kBlockBytes;
        if (origin + payload_sectors > SectorCount()) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: %s ends at sector %llu, past the %u sectors "
                "of the card", kEmmcSlotIndex, rom.filename.c_str(),
                static_cast<unsigned long long>(origin + payload_sectors),
                SectorCount());
        }
        if (origin < kMinStoreContainerOrigin) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: %s is written at sector %llu, which leaves "
                "no room for the partition table ahead of it", kEmmcSlotIndex,
                rom.filename.c_str(), static_cast<unsigned long long>(origin));
        }
        image_target_  = image.target;
        image_drive_   = image.drive;
        image_origin_  = static_cast<uint32_t>(origin);
        image_end_     = static_cast<uint32_t>(origin + payload_sectors);
        LOG(Boot, "eMMC card in slot %u: %s is written at part sector %u\n",
            kEmmcSlotIndex, rom.filename.c_str(), image_origin_);
    }

    void LoadUserAreaErase() {
        const DeviceConfig& cfg = emu_.Get<DeviceConfig>();
        const std::string& name = cfg.rom_lumia800_user_area_erase;
        if (name.empty()) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: rom.lumia800_user_area_erase is not set, "
                "so the content of the user area is not modeled", kEmmcSlotIndex);
        }
        const std::vector<uint8_t> bytes =
            ReadHostFileBytes(ResolveDeviceFile(cfg.device_name, name));
        if (bytes.empty()) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: rom.lumia800_user_area_erase %s cannot be "
                "read", kEmmcSlotIndex, name.c_str());
        }
        ri::EscoRange erase;
        if (!ri::EscoEraseRange(bytes, erase)) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: rom.lumia800_user_area_erase %s is not an "
                "erase package", kEmmcSlotIndex, name.c_str());
        }
        const ParsedRom& rom = PackagePrimary();
        if (erase.target != image_target_ || erase.drive != image_drive_) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: rom.lumia800_user_area_erase %s names "
                "target %u, drive %u, but %s is written to target %u, drive %u",
                kEmmcSlotIndex, name.c_str(), erase.target, erase.drive,
                rom.filename.c_str(), image_target_, image_drive_);
        }
        if (erase.start % cerf_mmc::kBlockBytes != 0u ||
            erase.size % cerf_mmc::kBlockBytes != 0u) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: rom.lumia800_user_area_erase %s erases "
                "0x%llX bytes at 0x%llX, which is not whole sectors",
                kEmmcSlotIndex, name.c_str(),
                static_cast<unsigned long long>(erase.size),
                static_cast<unsigned long long>(erase.start));
        }
        const uint64_t start = erase.start / cerf_mmc::kBlockBytes;
        const uint64_t count = erase.size / cerf_mmc::kBlockBytes;
        if (start < image_end_) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: rom.lumia800_user_area_erase %s starts "
                "before the end of the %zu payload bytes of %s, and only an erase "
                "range past the payload is modeled", kEmmcSlotIndex, name.c_str(),
                rom.wmstore_payload_bytes, rom.filename.c_str());
        }
        if (start >= SectorCount()) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: rom.lumia800_user_area_erase %s starts at "
                "sector %llu, past the %u sectors of the card", kEmmcSlotIndex,
                name.c_str(), static_cast<unsigned long long>(start),
                SectorCount());
        }
        const uint64_t end  = std::min<uint64_t>(start + count, SectorCount());
        const uint64_t unit = kFlasherEraseUnit / cerf_mmc::kBlockBytes;
        const uint64_t hw_start =
            std::min<uint64_t>((start + unit - 1u) / unit * unit, end);
        const uint64_t hw_end = std::max<uint64_t>(end / unit * unit, hw_start);
        erase_start_    = static_cast<uint32_t>(start);
        erase_end_      = static_cast<uint32_t>(end);
        hw_erase_start_ = static_cast<uint32_t>(hw_start);
        hw_erase_end_   = static_cast<uint32_t>(hw_end);
        LOG(Boot, "eMMC card in slot %u: %s erases sectors [%u, %u), hardware "
                  "erase [%u, %u)\n", kEmmcSlotIndex, name.c_str(), erase_start_,
            erase_end_, hw_erase_start_, hw_erase_end_);
    }

    uint8_t UnshippedByte(uint32_t sector) const {
        if (sector < erase_start_ || sector >= erase_end_) return kUnshippedSectorFill;
        if (sector >= hw_erase_start_ && sector < hw_erase_end_) return ErasedByte();
        return kFlasherWriteEraseFill;
    }

    void ReadStoreContainerSector(uint32_t sector, uint8_t* out) {
        std::memset(out, 0, cerf_mmc::kBlockBytes);
        if (sector == 0u) {
            out[kMbrEntryTypeOff] = kPartitionExtended;
            PutLe32(out + kMbrEntryLbaOff, image_origin_ - 1u);
        } else if (sector == image_origin_ - 1u) {
            out[kMbrEntryTypeOff] = kPartitionStore;
            PutLe32(out + kMbrEntryLbaOff, kEbrStoreRelativeLba);
        } else {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: sector %u lies ahead of the store at "
                "sector %u, and only its partition table is modeled",
                kEmmcSlotIndex, sector, image_origin_);
        }
        out[kMbrSignatureOff]      = kMbrSignature0;
        out[kMbrSignatureOff + 1u] = kMbrSignature1;
    }

    uint32_t image_target_   = 0u;
    uint32_t image_drive_    = 0u;
    uint32_t image_origin_   = 0u;
    uint32_t image_end_      = 0u;
    uint32_t erase_start_    = 0u;
    uint32_t erase_end_      = 0u;
    uint32_t hw_erase_start_ = 0u;
    uint32_t hw_erase_end_   = 0u;
};

}  // namespace

REGISTER_SERVICE_AS(NokiaLumia800Emmc, MmcCard);
