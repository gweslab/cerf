#include "cerf_virt_addr_map.h"
#include "cerf_virt_folder_share_regs.h"
#include "cerf_virt_utf16_window.h"
#include "folder_share_stage.h"
#include "folder_share_files.h"
#include "folder_share_dir.h"

#include "../peripheral_base.h"
#include "../peripheral_dispatcher.h"
#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/folder_share_config.h"
#include "../../core/log.h"
#include "../../state/state_stream.h"

#include <string>

using namespace CerfVirt;

namespace {

constexpr uint32_t kMountBytes = kFsMountPointMaxWchars * sizeof(uint16_t);

class CerfVirtFolderShare : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<DeviceConfig>().guest_additions;
    }

    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override {
        return emu_.Get<BoardContext>().GuestAdditionsWindowBase() + CerfVirt::kFolderShareOffset;
    }
    uint32_t MmioSize() const override { return CerfVirt::kFolderShareSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        switch (off) {
            case kFsIoPending:    return 0u;
            case kFsResult:       return result_;
            case kFsEnabled:      return emu_.Get<FolderShareConfig>().Enabled() ? 1u : 0u;
            case kFsGeneration:
                emu_.Get<FolderShareFiles>().ReconcileGeneration();
                emu_.Get<FolderShareDir>().ReconcileGeneration();
                return emu_.Get<FolderShareConfig>().Generation();
            default: break;
        }
        if (off >= kFsMountPoint && off + 4u <= kFsMountPoint + kMountBytes) {
            RefreshMount();
            return Utf16WindowWord(mount_, (off - kFsMountPoint) / 2u);
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    uint8_t ReadByte(uint32_t addr) override {
        const uint32_t w = ReadWord(addr & ~3u);
        return (uint8_t)(w >> ((addr & 3u) * 8u));
    }
    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t w = ReadWord(addr & ~3u);
        return (uint16_t)(w >> ((addr & 2u) * 8u));
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        switch (off) {
            case kFsServerPbAddr: break;
            case kFsCode:         HandleCode(value); break;
            default:              HaltUnsupportedAccess("WriteWord", addr, value);
        }
    }

    void SaveState(StateWriter& w) override {
        w.Write(result_);
        emu_.Get<FolderShareFiles>().SaveState(w);
    }
    void RestoreState(StateReader& r) override {
        r.Read(result_);
        emu_.Get<FolderShareFiles>().RestoreState(r);
        emu_.Get<FolderShareDir>().CloseAll();
    }

private:
    void RefreshMount() {
        auto& cfg = emu_.Get<FolderShareConfig>();
        const uint32_t g = cfg.Generation();
        if (mount_inited_ && g == mount_gen_) return;
        mount_gen_ = g;
        mount_inited_ = true;
        mount_ = cfg.MountPoint().substr(0, kFsMountPointMaxWchars - 1);
    }

    void HandleCode(uint32_t code) {
        if (code == kServerPollCompletion) return;

        emu_.Get<FolderShareFiles>().ReconcileGeneration();
        emu_.Get<FolderShareDir>().ReconcileGeneration();

        if (!emu_.Get<FolderShareConfig>().Enabled()) {
            result_ = kErrorGeneralFailure;
            return;
        }

        CerfVirt::ServerPB& pb = *emu_.Get<FolderShareStage>().Pb();
        if (pb.fStructureSize != sizeof(pb)) {
            LOG(Cerf, "[FolderShare] ServerPB fStructureSize %u != %u\n",
                pb.fStructureSize, (unsigned)sizeof(pb));
            CerfFatalExit();
        }

#if CERF_DEV_MODE
        LOG(GuestAdditions, "[FolderShare] >> op=0x%X name='%ls' idx=%d tid=0x%X\n",
            code, reinterpret_cast<const wchar_t*>(pb.fLfn.fName),
            (int)pb.fIndex, pb.fFindTransactionID);
#endif
        uint32_t r;
        if (FolderShareFiles::Owns(code))
            r = emu_.Get<FolderShareFiles>().Run(code, pb);
        else if (FolderShareDir::Owns(code))
            r = emu_.Get<FolderShareDir>().Run(code, pb);
        else {
            LOG(Cerf, "[FolderShare] unmodeled op 0x%X\n", code);
            CerfFatalExit();
        }

        result_ = r;
#if CERF_DEV_MODE
        LOG(GuestAdditions, "[FolderShare] op=0x%X name='%ls' nlen=%u attr=0x%X sz=%u "
            "time=0x%X ctime=0x%X h=%u pos=%u result=0x%X\n",
            code, reinterpret_cast<const wchar_t*>(pb.fLfn.fName), pb.fLfn.fNameLength,
            pb.fFileAttributes, pb.fSize, pb.fFileTimeDate, pb.fFileCreateTimeDate,
            pb.fHandle, pb.fPosition, r);
#endif
    }

    uint32_t result_      = 0;
    uint32_t mount_gen_   = 0;
    bool     mount_inited_ = false;
    std::wstring mount_;
};

REGISTER_SERVICE(CerfVirtFolderShare);

}
