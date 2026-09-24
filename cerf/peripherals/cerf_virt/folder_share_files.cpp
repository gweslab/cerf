#include "folder_share_files.h"

#include "folder_share_path.h"
#include "folder_share_stage.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/folder_share_config.h"
#include "../../core/log.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/state_stream.h"

#include <cstring>
#include <string>

using namespace CerfVirt;

REGISTER_SERVICE(FolderShareFiles);

FolderShareFiles::~FolderShareFiles() {
    CloseAll();
}

bool FolderShareFiles::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

void FolderShareFiles::OnReady() {
    emu_.Get<GuestCpuReset>().RegisterResetListener(
        [this](ResetLineKind) { CloseAll(); });
}

void FolderShareFiles::CloseAll() {
    for (int i = 0; i < kMaxFd; ++i) {
        if (files_[i].h == INVALID_HANDLE_VALUE) continue;
        CloseHandle(files_[i].h);
        files_[i].h = INVALID_HANDLE_VALUE;
        files_[i].name.clear();
    }
}

void FolderShareFiles::ReconcileGeneration() {
    const uint32_t g = emu_.Get<FolderShareConfig>().Generation();
    if (g != config_generation_) {
        config_generation_ = g;
        CloseAll();
    }
}

void FolderShareFiles::SaveState(StateWriter& w) {
    w.Write("open_seq", open_seq_);
}

void FolderShareFiles::RestoreState(StateReader& r) {
    r.Read("open_seq", open_seq_);
    CloseAll();
}

FolderShareFiles::Slot* FolderShareFiles::SlotFor(uint16_t handle) {
    const uint16_t idx = handle & 0x3Fu;
    if (idx >= (uint16_t)kMaxFd) return nullptr;
    Slot& s = files_[idx];
    if (s.h == INVALID_HANDLE_VALUE) return nullptr;
    if ((uint16_t)(handle >> 6) != s.seq) return nullptr;
    return &s;
}

bool FolderShareFiles::Owns(uint32_t code) {
    return code == kServerGetDriveConfig || code == kServerCreate ||
           code == kServerOpen || code == kServerRead ||
           code == kServerWrite || code == kServerSetEOF ||
           code == kServerClose || code == kServerGetSpace ||
           code == kServerGetFCBInfo || code == kServerGetMaxIOSize;
}

uint32_t FolderShareFiles::Run(uint32_t code, ServerPB& pb) {
    switch (code) {
        case kServerGetDriveConfig: return GetDriveConfig(pb);
        case kServerCreate:         return Create(pb);
        case kServerOpen:           return Open(pb);
        case kServerRead:           return Read(pb);
        case kServerWrite:          return Write(pb);
        case kServerSetEOF:         return SetEof(pb);
        case kServerClose:          return Close(pb);
        case kServerGetSpace:       return GetSpace(pb);
        case kServerGetFCBInfo:     return GetFcbInfo(pb);
        case kServerGetMaxIOSize:
            LOG(Cerf, "[FolderShareFiles] GET_MAX_IO_SIZE has no issuing client\n");
            CerfFatalExit();
        default: break;
    }
    LOG(Cerf, "[FolderShareFiles] Run called with unowned op 0x%X\n", code);
    CerfFatalExit();
}

uint16_t FolderShareFiles::AllocSlot() {
    for (int i = 0; i < kMaxFd; ++i) {
        if (files_[i].h == INVALID_HANDLE_VALUE) return (uint16_t)i;
    }
    return (uint16_t)kMaxFd;
}

uint16_t FolderShareFiles::GetDriveConfig(ServerPB&) {
    LOG(Cerf, "[FolderShareFiles] GET_DRIVE_CONFIG has no issuing client\n");
    CerfFatalExit();
}

uint16_t FolderShareFiles::Create(ServerPB& pb) {
    std::wstring path;
    uint16_t e = emu_.Get<FolderSharePath>().ToWin32Path(
        pb.fLfn.fName, pb.fLfn.fNameLength, path);
    if (e != kErrorNoError) return e;
    HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                           CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return FolderSharePath::CeError(GetLastError());
    CloseHandle(h);
    return kErrorNoError;
}

uint16_t FolderShareFiles::Open(ServerPB& pb) {
    std::wstring path;
    uint16_t e = emu_.Get<FolderSharePath>().ToWin32Path(
        pb.fLfn.fName, pb.fLfn.fNameLength, path);
    if (e != kErrorNoError) return e;

    const uint16_t slot = AllocSlot();
    if (slot >= (uint16_t)kMaxFd) return kErrorTooManyOpenFiles;

    DWORD access;
    switch (pb.fOpenMode & 0x03u) {
        case kOpenAccessReadOnly:  access = GENERIC_READ; break;
        case kOpenAccessWriteOnly: access = GENERIC_WRITE; break;
        case kOpenAccessReadWrite: access = GENERIC_READ | GENERIC_WRITE; break;
        default:
            LOG(Cerf, "[FolderShareFiles] Open with undefined access mode 0x%X\n",
                pb.fOpenMode);
            CerfFatalExit();
    }
    DWORD share;
    switch (pb.fOpenMode & 0x70u) {
        case kOpenShareDenyReadWrite: share = 0; break;
        case kOpenShareDenyWrite:     share = FILE_SHARE_READ; break;
        case kOpenShareDenyRead:      share = FILE_SHARE_WRITE; break;
        case kOpenShareDenyNone:      share = FILE_SHARE_READ | FILE_SHARE_WRITE; break;
        default:
            LOG(Cerf, "[FolderShareFiles] Open with undefined share mode 0x%X\n",
                pb.fOpenMode);
            CerfFatalExit();
    }

    HANDLE h = CreateFileW(path.c_str(), access, share, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE)
        return FolderSharePath::CeError(GetLastError());

    open_seq_ = (uint16_t)((open_seq_ + 1u) & 0x3FFu);
    files_[slot].h   = h;
    files_[slot].seq = open_seq_;
    files_[slot].name.assign(
        reinterpret_cast<const wchar_t*>(pb.fLfn.fName),
        pb.fLfn.fNameLength / sizeof(uint16_t));
    pb.fHandle = (uint16_t)(slot | (open_seq_ << 6));
    return kErrorNoError;
}

uint16_t FolderShareFiles::Read(ServerPB& pb) {
    Slot* slot = SlotFor(pb.fHandle);
    if (!slot) return kErrorInvalidHandle;
    if (pb.fSize > kFolderShareMaxReadWriteSize) {
        LOG(Cerf, "[FolderShareFiles] Read of %u bytes exceeds the stage\n",
            pb.fSize);
        CerfFatalExit();
    }
    HANDLE h = slot->h;
    LARGE_INTEGER pos;
    pos.QuadPart = pb.fPosition;
    if (!SetFilePointerEx(h, pos, nullptr, FILE_BEGIN))
        return FolderSharePath::CeError(GetLastError());
    DWORD done = 0;
    if (!ReadFile(h, emu_.Get<FolderShareStage>().IoBuf(), pb.fSize, &done,
                  nullptr))
        return FolderSharePath::CeError(GetLastError());
    pb.fSize = done;
    return kErrorNoError;
}

uint16_t FolderShareFiles::Write(ServerPB& pb) {
    Slot* slot = SlotFor(pb.fHandle);
    if (!slot) return kErrorInvalidHandle;
    if (pb.fSize > kFolderShareMaxReadWriteSize) {
        LOG(Cerf, "[FolderShareFiles] Write of %u bytes exceeds the stage\n",
            pb.fSize);
        CerfFatalExit();
    }
    HANDLE h = slot->h;
    LARGE_INTEGER pos;
    pos.QuadPart = pb.fPosition;
    if (!SetFilePointerEx(h, pos, nullptr, FILE_BEGIN))
        return FolderSharePath::CeError(GetLastError());
    DWORD done = 0;
    if (!WriteFile(h, emu_.Get<FolderShareStage>().IoBuf(), pb.fSize, &done,
                   nullptr))
        return FolderSharePath::CeError(GetLastError());
    pb.fSize = done;
    return kErrorNoError;
}

uint16_t FolderShareFiles::SetEof(ServerPB& pb) {
    Slot* slot = SlotFor(pb.fHandle);
    if (!slot) return kErrorInvalidHandle;
    HANDLE h = slot->h;
    LARGE_INTEGER pos;
    pos.QuadPart = pb.fPosition;
    if (!SetFilePointerEx(h, pos, nullptr, FILE_BEGIN))
        return FolderSharePath::CeError(GetLastError());
    if (!SetEndOfFile(h))
        return FolderSharePath::CeError(GetLastError());
    return kErrorNoError;
}

uint16_t FolderShareFiles::Close(ServerPB& pb) {
    Slot* slot = SlotFor(pb.fHandle);
    if (!slot) return kErrorInvalidHandle;
    CloseHandle(slot->h);
    slot->h = INVALID_HANDLE_VALUE;
    slot->name.clear();
    return kErrorNoError;
}

uint16_t FolderShareFiles::GetFcbInfo(ServerPB& pb) {
    Slot* slot = SlotFor(pb.fHandle);
    if (!slot) return kErrorInvalidHandle;
    BY_HANDLE_FILE_INFORMATION fi;
    if (!GetFileInformationByHandle(slot->h, &fi))
        return FolderSharePath::CeError(GetLastError());
    pb.fFileAttributes     = FolderSharePath::CeFileAttributes(fi.dwFileAttributes);
    pb.fSize               = FolderSharePath::CeFileSize(fi.nFileSizeHigh, fi.nFileSizeLow);
    pb.fFileTimeDate       = FolderSharePath::FiletimeToLong(fi.ftLastWriteTime);
    pb.fFileCreateTimeDate = FolderSharePath::FiletimeToLong(fi.ftCreationTime);
    const std::wstring& name = slot->name;
    size_t n = name.size();
    if (n > kMaxLfn) n = kMaxLfn;
    memcpy(pb.fLfn.fName, name.data(), n * sizeof(uint16_t));
    pb.fLfn.fName[n]    = 0;
    pb.fLfn.fNameLength = (uint16_t)(n * sizeof(uint16_t));
    return kErrorNoError;
}

uint16_t FolderShareFiles::GetSpace(ServerPB& pb) {
    std::wstring root = emu_.Get<FolderShareConfig>().HostRoot();
    ULARGE_INTEGER avail, total;
    if (!GetDiskFreeSpaceExW(root.c_str(), &avail, &total, nullptr))
        return FolderSharePath::CeError(GetLastError());
    const uint64_t cluster = 512ull * 64ull;
    uint64_t total_cl = total.QuadPart / cluster;
    uint64_t avail_cl = avail.QuadPart / cluster;
    if (total_cl > 0xFFFFFFFFull) total_cl = 0xFFFFFFFFull;
    if (avail_cl > 0xFFFFFFFFull) avail_cl = 0xFFFFFFFFull;
    pb.fPosition = (uint32_t)total_cl;
    pb.fSize     = (uint32_t)avail_cl;
    return kErrorNoError;
}
