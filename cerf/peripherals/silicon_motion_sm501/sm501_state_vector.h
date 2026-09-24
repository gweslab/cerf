#pragma once

#include "../../state/state_stream.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace siemens_mp377 {

template <typename T>
void WriteSm501VectorState(StateWriter& writer, const char* count_name, const char* name,
                           const std::vector<T>& values) {
    writer.Write<uint64_t>(count_name, values.size());
    writer.WriteBytes(name, values.data(), values.size() * sizeof(T));
}

template <typename T>
void ReadSm501VectorState(StateReader& reader, const char* count_name, const char* name,
                          std::vector<T>& values, size_t max_elements) {
    uint64_t size = 0;
    reader.Read(count_name, size);
    if (size > static_cast<uint64_t>(max_elements))
        reader.Reject("SM501 %s of %llu elements, at most %zu", name,
                      static_cast<unsigned long long>(size), max_elements);
    values.resize(static_cast<size_t>(size));
    reader.ReadBytes(name, values.data(), values.size() * sizeof(T));
}

} // namespace siemens_mp377
