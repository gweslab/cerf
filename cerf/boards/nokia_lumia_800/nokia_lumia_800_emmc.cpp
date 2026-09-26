#include "../../peripherals/sk_hynix_h26m52002ckr/sk_hynix_h26m52002ckr.h"

#include "../../boot/rom_parser_service.h"
#include "../../boot/rom_wmstore_parse.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/cerf_paths.h"
#include "../../core/device_config.h"
#include "../../core/fatal.h"
#include "../../core/host_file_bytes.h"
#include "../../core/log.h"
#include "../../storage/disk_image.h"
#include "../board_context.h"
#include "nokia_lumia_800_id.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace {

namespace ri = cerf::rom_image_parse;

constexpr uint32_t kEmmcSlotIndex = 0u;

constexpr uint64_t kFlasherEraseUnit      = 0x800000u;
constexpr uint8_t  kFlasherWriteEraseFill = 0xFFu;
constexpr uint32_t kSeedChunkSectors      = 2048u;

constexpr uint32_t kMbrEntryTypeOff    = 450u;
constexpr uint32_t kMbrEntryLbaOff     = 454u;
constexpr uint32_t kMbrSignatureOff    = 510u;
constexpr uint8_t  kMbrSignature0      = 0x55u;
constexpr uint8_t  kMbrSignature1      = 0xAAu;
constexpr uint8_t  kPartitionExtended  = 0x05u;
constexpr uint8_t  kPartitionStore     = 0x48u;
constexpr uint32_t kEbrStoreRelativeLba = 1u;
constexpr uint32_t kMinStoreContainerOrigin = 2u;

constexpr uint32_t kHoleMarkerSector = 1u;
constexpr char     kHoleMarkerMagic[] = "CERF-UNMODELED:";
constexpr uint32_t kHoleMarkerMagicBytes = sizeof(kHoleMarkerMagic);
constexpr uint32_t kHoleMarkerEndOff = kHoleMarkerMagicBytes;
constexpr uint32_t kHoleMarkerBytes  = kHoleMarkerEndOff + 4u;
static_assert(kHoleMarkerMagicBytes == 16u);

class NokiaLumia800Emmc : public SkHynixH26m52002ckr {
public:
    using SkHynixH26m52002ckr::SkHynixH26m52002ckr;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NokiaLumia800;
    }

    uint32_t SlotIndex() const override { return kEmmcSlotIndex; }

    void OnReady() override {
        SkHynixH26m52002ckr::OnReady();
        OpenStore();
    }

protected:
    void ReadBlock(uint32_t sector, uint8_t* out) override {
        if (sector >= kHoleMarkerSector && sector < hole_end_) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: sector %u lies in [%u, %u), which the seed of "
                "storage.emmc %s did not model", kEmmcSlotIndex, sector,
                kHoleMarkerSector, hole_end_, store_path_.c_str());
        }
        if (!store_.ReadSectors(sector, 1u, out)) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: sector %u cannot be read from %s",
                kEmmcSlotIndex, sector, store_path_.c_str());
        }
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

    void OpenStore() {
        const DeviceConfig& cfg = emu_.Get<DeviceConfig>();
        store_path_ = ResolveDeviceFile(cfg.device_name, cfg.storage_emmc);
        if (HostFileNonEmpty(store_path_)) {
            LOG(Boot, "eMMC card in slot %u: using storage.emmc %s\n",
                kEmmcSlotIndex, store_path_.c_str());
        } else {
            SeedStore();
        }
        OpenCardImage(store_, store_path_);
        LoadHoleMarker();
    }

    void LoadHoleMarker() {
        uint8_t sector[cerf_mmc::kBlockBytes];
        if (!store_.ReadSectors(kHoleMarkerSector, 1u, sector)) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: sector %u cannot be read from storage.emmc %s",
                kEmmcSlotIndex, kHoleMarkerSector, store_path_.c_str());
        }
        if (std::memcmp(sector, kHoleMarkerMagic, kHoleMarkerMagicBytes) != 0) return;
        const uint32_t end = cerf::le::U32(sector, kHoleMarkerEndOff);
        const bool tail_clear = std::all_of(sector + kHoleMarkerBytes, std::end(sector),
                                            [](uint8_t b) { return b == 0u; });
        if (end <= kHoleMarkerSector || end > SectorCount() || !tail_clear) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: sector %u of storage.emmc %s starts with the "
                "seed marker, and the rest of it is not a marker for the %u sectors "
                "of the card", kEmmcSlotIndex, kHoleMarkerSector, store_path_.c_str(),
                SectorCount());
        }
        hole_end_ = end;
        LOG(Boot, "eMMC card in slot %u: storage.emmc %s marks sectors [%u, %u) as "
                  "not modeled by its seed\n", kEmmcSlotIndex, store_path_.c_str(),
            kHoleMarkerSector, hole_end_);
    }

    void OpenCardImage(DiskImage& image, const std::string& path) {
        if (!image.Open(path, uint64_t(SectorCount()) * cerf_mmc::kBlockBytes)) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: storage.emmc %s cannot be opened",
                kEmmcSlotIndex, path.c_str());
        }
        if (image.SectorCount() != SectorCount()) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: storage.emmc %s holds %llu sectors, and the "
                "card has %u", kEmmcSlotIndex, path.c_str(),
                static_cast<unsigned long long>(image.SectorCount()), SectorCount());
        }
    }

    void SeedStore() {
        const std::string seeding = store_path_ + ".seeding";
        LOG(Boot, "eMMC card in slot %u: seeding storage.emmc %s\n",
            kEmmcSlotIndex, store_path_.c_str());
        LoadImageOrigin();
        LoadUserAreaErase();
        const std::wstring seeding_w = Utf8ToWide(seeding.c_str());
        if (!DeleteFileW(seeding_w.c_str())) {
            const DWORD err = GetLastError();
            if (err != ERROR_FILE_NOT_FOUND && err != ERROR_PATH_NOT_FOUND) {
                emu_.Get<Fatal>().Die(
                    "eMMC card in slot %u: %s is left from an earlier seed and "
                    "cannot be deleted (error %lu)", kEmmcSlotIndex, seeding.c_str(),
                    static_cast<unsigned long>(err));
            }
        }
        {
            DiskImage image;
            OpenCardImage(image, seeding);
            SeedStoreContainer(image);
            SeedHoleMarker(image);
            SeedPayload(image);
            SeedErase(image);
        }
        if (!MoveFileExW(seeding_w.c_str(), Utf8ToWide(store_path_.c_str()).c_str(),
                         MOVEFILE_REPLACE_EXISTING)) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: the seeded card image %s cannot be moved to "
                "storage.emmc %s", kEmmcSlotIndex, seeding.c_str(),
                store_path_.c_str());
        }
        LOG(Boot, "eMMC card in slot %u: storage.emmc %s seeded\n",
            kEmmcSlotIndex, store_path_.c_str());
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

    void SeedStoreContainer(DiskImage& image) {
        uint8_t mbr[cerf_mmc::kBlockBytes] = {};
        mbr[kMbrEntryTypeOff] = kPartitionExtended;
        cerf::le::Put32(mbr + kMbrEntryLbaOff, image_origin_ - 1u);
        mbr[kMbrSignatureOff]      = kMbrSignature0;
        mbr[kMbrSignatureOff + 1u] = kMbrSignature1;
        WriteSeed(image, 0u, 1u, mbr);

        uint8_t ebr[cerf_mmc::kBlockBytes] = {};
        ebr[kMbrEntryTypeOff] = kPartitionStore;
        cerf::le::Put32(ebr + kMbrEntryLbaOff, kEbrStoreRelativeLba);
        ebr[kMbrSignatureOff]      = kMbrSignature0;
        ebr[kMbrSignatureOff + 1u] = kMbrSignature1;
        WriteSeed(image, image_origin_ - 1u, 1u, ebr);
    }

    void SeedHoleMarker(DiskImage& image) {
        const uint32_t end = image_origin_ - 1u;
        if (end <= kHoleMarkerSector) return;
        uint8_t marker[cerf_mmc::kBlockBytes] = {};
        std::memcpy(marker, kHoleMarkerMagic, kHoleMarkerMagicBytes);
        cerf::le::Put32(marker + kHoleMarkerEndOff, end);
        WriteSeed(image, kHoleMarkerSector, 1u, marker);
    }

    void SeedPayload(DiskImage& image) {
        const ParsedRom& rom = PackagePrimary();
        if (rom.wmstore_payload_bytes % cerf_mmc::kBlockBytes != 0u) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: the %zu payload bytes of %s end inside a "
                "sector, and the rest of that sector is not modeled",
                kEmmcSlotIndex, rom.wmstore_payload_bytes, rom.filename.c_str());
        }
        const uint8_t* payload = rom.raw.data() + rom.wmstore_payload_off;
        const uint32_t sectors =
            static_cast<uint32_t>(rom.wmstore_payload_bytes / cerf_mmc::kBlockBytes);
        for (uint32_t done = 0; done < sectors;) {
            const uint32_t n = (std::min)(kSeedChunkSectors, sectors - done);
            WriteSeed(image, image_origin_ + done, n,
                      payload + size_t(done) * cerf_mmc::kBlockBytes);
            done += n;
        }
    }

    void SeedErase(DiskImage& image) {
        FillSeed(image, erase_start_, hw_erase_start_, kFlasherWriteEraseFill);
        FillSeed(image, hw_erase_start_, hw_erase_end_, ErasedByte());
        FillSeed(image, hw_erase_end_, erase_end_, kFlasherWriteEraseFill);
    }

    void FillSeed(DiskImage& image, uint32_t first, uint32_t end, uint8_t fill) {
        if (first >= end || fill == 0u) return;
        const std::vector<uint8_t> chunk(size_t(kSeedChunkSectors) * cerf_mmc::kBlockBytes,
                                         fill);
        for (uint32_t at = first; at < end;) {
            const uint32_t n = (std::min)(kSeedChunkSectors, end - at);
            WriteSeed(image, at, n, chunk.data());
            at += n;
        }
    }

    void WriteSeed(DiskImage& image, uint32_t sector, uint32_t count,
                   const void* src) {
        if (!image.WriteSectors(sector, count, src)) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: the card image for storage.emmc %s cannot be "
                "written at sector %u", kEmmcSlotIndex, store_path_.c_str(), sector);
        }
    }

    DiskImage   store_;
    std::string store_path_;
    uint32_t hole_end_       = 0u;
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
