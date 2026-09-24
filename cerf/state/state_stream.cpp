#include "state_stream.h"

#include "../core/log.h"

#include <cstdarg>
#include <cstddef>
#include <cstdio>

namespace {
constexpr DWORD kIoChunk = 0x40000000u;

const char* FieldKindName(uint8_t kind) {
    switch (kind) {
        case kStateFieldPod:   return "a value";
        case kStateFieldBytes: return "a byte block";
        default:               return "an unknown field kind";
    }
}
}

StateWriter::StateWriter(const std::wstring& path)
    : final_path_(path), temp_path_(path + L".tmp") {
    file_ = CreateFileW(temp_path_.c_str(), GENERIC_WRITE, 0, nullptr,
                        CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_ == INVALID_HANDLE_VALUE) {
        LOG(Caution, "StateWriter: CreateFile('%ls') failed gle=%lu\n",
            temp_path_.c_str(), GetLastError());
        return;
    }
    ok_ = true;
}

StateWriter::~StateWriter() {
    CloseHandle_();
    if (!committed_)
        DeleteFileW(temp_path_.c_str());
}

void StateWriter::CloseHandle_() {
    if (file_ != INVALID_HANDLE_VALUE) {
        CloseHandle(file_);
        file_ = INVALID_HANDLE_VALUE;
    }
}

void StateWriter::WriteRaw(const void* src, size_t n) {
    if (!ok_) return;
    const auto* p = static_cast<const uint8_t*>(src);
    while (n > 0) {
        const DWORD chunk = n > kIoChunk ? kIoChunk : static_cast<DWORD>(n);
        DWORD wrote = 0;
        if (!WriteFile(file_, p, chunk, &wrote, nullptr) || wrote != chunk) {
            LOG(Caution, "StateWriter: WriteFile failed gle=%lu (%lu/%lu)\n",
                GetLastError(), wrote, chunk);
            ok_ = false;
            return;
        }
        p              += chunk;
        n              -= chunk;
        bytes_written_ += chunk;
    }
}

void StateWriter::WriteTag(uint8_t kind, const char* name, uint64_t size) {
    const StateFieldTag tag{kind, StateFieldNameHash(name), size};
    WriteRaw(&tag, sizeof(tag));
}

void StateWriter::WriteBlock(const char* name, const void* src, size_t n) {
    WriteTag(kStateFieldBytes, name, n);
    if (n) WriteRaw(src, n);
}

void StateWriter::BeginFrame(uint32_t id) {
    frames_.push_back(bytes_written_);
    const StateFrameHeader header{id, 0};
    WriteRaw(&header, sizeof(header));
}

void StateWriter::EndFrame() {
    if (frames_.empty()) {
        LOG(Caution, "StateWriter: EndFrame with no open frame\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint64_t header_off = frames_.back();
    frames_.pop_back();
    const uint64_t length = bytes_written_ - header_off - sizeof(StateFrameHeader);
    PatchAt(header_off + offsetof(StateFrameHeader, length), &length, sizeof(length));
}

void StateWriter::PatchAt(uint64_t offset, const void* src, size_t n) {
    if (!ok_) return;
    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(file_, li, nullptr, FILE_BEGIN)) {
        LOG(Caution, "StateWriter: PatchAt seek failed gle=%lu\n", GetLastError());
        ok_ = false;
        return;
    }
    DWORD wrote = 0;
    if (!WriteFile(file_, src, static_cast<DWORD>(n), &wrote, nullptr) || wrote != n) {
        LOG(Caution, "StateWriter: PatchAt write failed gle=%lu\n", GetLastError());
        ok_ = false;
        return;
    }
    LARGE_INTEGER end{};
    if (!SetFilePointerEx(file_, end, nullptr, FILE_END)) {
        LOG(Caution, "StateWriter: PatchAt seek-back failed gle=%lu\n", GetLastError());
        ok_ = false;
    }
}

bool StateWriter::Commit() {
    if (!frames_.empty()) {
        LOG(Caution, "StateWriter: Commit with %zu open frames\n", frames_.size());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    if (!ok_) {
        CloseHandle_();
        DeleteFileW(temp_path_.c_str());
        return false;
    }
    CloseHandle_();
    if (!MoveFileExW(temp_path_.c_str(), final_path_.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        LOG(Caution, "StateWriter: MoveFileEx('%ls' -> '%ls') failed gle=%lu\n",
            temp_path_.c_str(), final_path_.c_str(), GetLastError());
        DeleteFileW(temp_path_.c_str());
        ok_ = false;
        return false;
    }
    committed_ = true;
    return true;
}

StateReader::StateReader(const std::wstring& path) {
    file_ = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file_ == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(file_, &sz)) return;
    file_size_ = static_cast<uint64_t>(sz.QuadPart);
    ok_ = true;
}

StateReader::~StateReader() {
    if (file_ != INVALID_HANDLE_VALUE)
        CloseHandle(file_);
}

void StateReader::Reject(const char* fmt, ...) {
    ok_ = false;
    char reason[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(reason, sizeof(reason), fmt, ap);
    va_end(ap);
    std::string where = "image";
    for (const Frame& f : frames_) {
        char id[16];
        snprintf(id, sizeof(id), "/0x%X", f.id);
        where += id;
    }
    char field[96];
    snprintf(field, sizeof(field), " field %u '%s'", fields_, field_name_);
    throw StateImageRejected(where + field + ": " + reason);
}

uint64_t StateReader::Remaining() const {
    const uint64_t limit = frames_.empty() ? file_size_ : frames_.back().end;
    return limit > pos_ ? limit - pos_ : 0;
}

void StateReader::ReadRaw(void* dst, size_t n) {
    if (!ok_) Reject("the image is not open");
    if (n > Remaining())
        Reject("the saved data ends %llu bytes short of what this build reads",
               static_cast<unsigned long long>(n - Remaining()));
    auto* p = static_cast<uint8_t*>(dst);
    while (n > 0) {
        const DWORD chunk = n > kIoChunk ? kIoChunk : static_cast<DWORD>(n);
        DWORD got = 0;
        if (!ReadFile(file_, p, chunk, &got, nullptr) || got != chunk)
            Reject("ReadFile failed gle=%lu (%lu/%lu)", GetLastError(), got, chunk);
        p    += chunk;
        n    -= chunk;
        pos_ += chunk;
    }
}

void StateReader::ExpectTag(uint8_t kind, const char* name, uint64_t size) {
    ++fields_;
    field_name_ = name;
    StateFieldTag tag{};
    ReadRaw(&tag, sizeof(tag));
    if (tag.name != StateFieldNameHash(name))
        Reject("the saved field at this position is a different field");
    if (tag.kind != kind || tag.size != size)
        Reject("saved %s of %llu bytes, this build reads %s of %llu bytes",
               FieldKindName(tag.kind), static_cast<unsigned long long>(tag.size),
               FieldKindName(kind), static_cast<unsigned long long>(size));
}

void StateReader::ReadBlock(const char* name, void* dst, size_t n) {
    ExpectTag(kStateFieldBytes, name, n);
    if (n) ReadRaw(dst, n);
}

uint32_t StateReader::EnterFrame() {
    StateFrameHeader header{};
    ReadRaw(&header, sizeof(header));
    if (header.length > Remaining())
        Reject("frame 0x%X claims %llu bytes past the end of its parent", header.id,
               static_cast<unsigned long long>(header.length - Remaining()));
    frames_.push_back(Frame{header.id, pos_ + header.length, fields_});
    fields_     = 0;
    field_name_ = "";
    return header.id;
}

void StateReader::LeaveFrame() {
    if (frames_.empty()) {
        LOG(Caution, "StateReader: LeaveFrame with no open frame\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    if (Remaining() != 0)
        Reject("this build leaves %llu saved bytes unread",
               static_cast<unsigned long long>(Remaining()));
    fields_     = frames_.back().parent_fields;
    field_name_ = "";
    frames_.pop_back();
}

void StateReader::SkipFrame() {
    if (frames_.empty()) {
        LOG(Caution, "StateReader: SkipFrame with no open frame\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    SeekTo(frames_.back().end);
    fields_     = frames_.back().parent_fields;
    field_name_ = "";
    frames_.pop_back();
}

void StateReader::SeekTo(uint64_t offset) {
    LARGE_INTEGER li;
    li.QuadPart = static_cast<LONGLONG>(offset);
    if (!SetFilePointerEx(file_, li, nullptr, FILE_BEGIN))
        Reject("seek to %llu failed gle=%lu", static_cast<unsigned long long>(offset),
               GetLastError());
    pos_ = offset;
}
