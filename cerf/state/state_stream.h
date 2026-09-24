#pragma once

#define NOMINMAX
#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

#pragma pack(push, 1)
struct StateFieldTag {
    uint8_t  kind;
    uint32_t name;
    uint64_t size;
};

struct StateFrameHeader {
    uint32_t id;
    uint64_t length;
};
#pragma pack(pop)

static_assert(sizeof(StateFieldTag) == 13, "StateFieldTag is an on-disk layout");
static_assert(sizeof(StateFrameHeader) == 12, "StateFrameHeader is an on-disk layout");

inline constexpr uint8_t kStateFieldPod   = 1;
inline constexpr uint8_t kStateFieldBytes = 2;

/* FNV-1a, RFC 9923 §2; 32-bit FNV_Prime and offset_basis, RFC 9923 §5. */
constexpr uint32_t StateFieldNameHash(const char* name) {
    uint32_t h = 0x811C9DC5u;
    for (; *name != '\0'; ++name)
        h = (h ^ static_cast<uint8_t>(*name)) * 0x01000193u;
    return h;
}

template <typename T>
struct StateScalar : std::bool_constant<std::is_arithmetic_v<T> || std::is_enum_v<T>> {};
template <typename T, size_t N>
struct StateScalar<T[N]> : StateScalar<T> {};
template <typename T, size_t N>
struct StateScalar<std::array<T, N>> : StateScalar<T> {};

class StateImageRejected : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

class StateWriter {
public:
    explicit StateWriter(const std::wstring& path);
    ~StateWriter();

    StateWriter(const StateWriter&)            = delete;
    StateWriter& operator=(const StateWriter&) = delete;

    bool Ok() const { return ok_; }

    template <typename T>
    void Write(const char* name, const T& v) {
        static_assert(StateScalar<T>::value,
                      "StateWriter::Write takes a scalar, an enum, or an array of them; "
                      "write a struct field by field.");
        WriteTag(kStateFieldPod, name, sizeof(T));
        WriteRaw(&v, sizeof(T));
    }

    template <typename T>
    void WriteBytes(const char* name, const T* src, size_t n) {
        static_assert(StateScalar<T>::value,
                      "StateWriter::WriteBytes takes a buffer of scalars or enums; "
                      "write a struct field by field.");
        WriteBlock(name, src, n);
    }

    void BeginFrame(uint32_t id);
    void EndFrame();

    bool Commit();

private:
    friend class Hibernation;

    void WriteRaw(const void* src, size_t n);
    void WriteBlock(const char* name, const void* src, size_t n);
    void WriteTag(uint8_t kind, const char* name, uint64_t size);
    void PatchAt(uint64_t offset, const void* src, size_t n);
    void CloseHandle_();

    std::wstring          final_path_;
    std::wstring          temp_path_;
    HANDLE                file_          = INVALID_HANDLE_VALUE;
    uint64_t              bytes_written_ = 0;
    std::vector<uint64_t> frames_;
    bool                  ok_            = false;
    bool                  committed_     = false;
};

class StateReader {
public:
    explicit StateReader(const std::wstring& path);
    ~StateReader();

    StateReader(const StateReader&)            = delete;
    StateReader& operator=(const StateReader&) = delete;

    bool Ok() const { return ok_; }

    template <typename T>
    void Read(const char* name, T& v) {
        static_assert(StateScalar<T>::value,
                      "StateReader::Read takes a scalar or an array of them; "
                      "read a struct field by field.");
        ExpectTag(kStateFieldPod, name, sizeof(T));
        ReadRaw(&v, sizeof(T));
    }

    template <typename T>
    void ReadBytes(const char* name, T* dst, size_t n) {
        static_assert(StateScalar<T>::value,
                      "StateReader::ReadBytes takes a buffer of scalars or enums; "
                      "read a struct field by field.");
        ReadBlock(name, dst, n);
    }

    uint32_t EnterFrame();
    void     LeaveFrame();
    void     SkipFrame();

    uint64_t Remaining() const;

    [[noreturn]] void Reject(const char* fmt, ...);

private:
    friend class Hibernation;

    struct Frame {
        uint32_t id;
        uint64_t end;
        uint32_t parent_fields;
    };

    void ReadRaw(void* dst, size_t n);
    void ReadBlock(const char* name, void* dst, size_t n);
    void ExpectTag(uint8_t kind, const char* name, uint64_t size);
    void SeekTo(uint64_t offset);

    HANDLE             file_       = INVALID_HANDLE_VALUE;
    uint64_t           pos_        = 0;
    uint64_t           file_size_  = 0;
    std::vector<Frame> frames_;
    uint32_t           fields_     = 0;
    const char*        field_name_ = "";
    bool               ok_         = false;
};

template <typename T>
struct StateStdArray : std::false_type {};
template <typename T, size_t N>
struct StateStdArray<std::array<T, N>> : std::true_type {};

class StateFieldBytes {
public:
    explicit constexpr StateFieldBytes(bool mark) : mark_(mark) {}
    template <typename T>
    constexpr void operator()(const char*, T& v) { Add(v); }
    template <typename T>
    constexpr void Skip(T& v) { Add(v); }
    size_t bytes = 0;
    bool   once  = true;
private:
    template <typename T>
    constexpr void Add(T& v) {
        bytes += sizeof(T);
        Touch(v);
    }
    template <typename T>
    constexpr void Touch(T& v) {
        if constexpr (std::is_array_v<T> || StateStdArray<T>::value) {
            for (auto& e : v) Touch(e);
        } else if constexpr (!std::is_arithmetic_v<T> && !std::is_enum_v<T>) {
            if (!mark_) return;
            const void* at = &v;
            for (size_t i = 0; i < object_count_; ++i)
                if (objects_[i] == at) once = false;
            if (object_count_ == kMaxObjects) { once = false; return; }
            objects_[object_count_++] = at;
        } else if (!mark_) {
            v = T{};
        } else {
            if (v != T{}) once = false;
            v = static_cast<T>(1);
        }
    }
    static constexpr size_t kMaxObjects = 32;
    bool        mark_;
    const void* objects_[kMaxObjects] = {};
    size_t      object_count_ = 0;
};

class StateWriteField {
public:
    explicit StateWriteField(StateWriter& w) : w_(w) {}
    template <typename T>
    void operator()(const char* name, const T& v) { w_.Write(name, v); }
    template <typename T>
    void Skip(const T&) {}
private:
    StateWriter& w_;
};

class StateReadField {
public:
    explicit StateReadField(StateReader& r) : r_(r) {}
    template <typename T>
    void operator()(const char* name, T& v) { r_.Read(name, v); }
    template <typename T>
    void Skip(const T&) {}
private:
    StateReader& r_;
};

template <typename T, typename Visit>
constexpr bool StateVisitCoversAllBytes(Visit visit) {
    T s{};
    StateFieldBytes clear(false);
    visit(s, clear);
    StateFieldBytes mark(true);
    visit(s, mark);
    return mark.once && mark.bytes == sizeof(T);
}
