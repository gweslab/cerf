#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace cerf::ce_imgfs_xpress {


std::vector<uint8_t> Decompress(const uint8_t* src,
                                size_t          src_size,
                                size_t          out_size);

}
