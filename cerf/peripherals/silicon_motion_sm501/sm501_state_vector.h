#pragma once

#include "../../state/state_stream.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace siemens_mp377 {

template <typename T> void WriteSm501VectorState(StateWriter& writer, const std::vector<T>& values) {
    const uint64_t size = static_cast<uint64_t>(values.size());
    writer.Write(size);
    if (size) writer.WriteBytes(values.data(), static_cast<size_t>(size * sizeof(T)));
}

template <typename T>
uint64_t ReadSm501VectorState(StateReader& reader, std::vector<T>& values, size_t max_expected) {
    uint64_t size = 0;
    reader.Read(size);
    if (size <= static_cast<uint64_t>(max_expected)) {
        values.resize(static_cast<size_t>(size));
        if (size) reader.ReadBytes(values.data(), static_cast<size_t>(size * sizeof(T)));
    }
    return size;
}

} // namespace siemens_mp377
