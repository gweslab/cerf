#pragma once

#include <cstdint>
#include <vector>

class PeImage;

namespace cerf::ce_image_relocator {

/* MUST run before injecting ROM-module bytes — the kernel's
   Relocate() is gated on `e32_vbase != BasePtr` and our injection
   equalises them, so without this the image keeps its link-time
   absolute pointers and faults on first use. */
void ApplyRelocations(std::vector<uint8_t>& bytes,
                      const PeImage&        pe,
                      int32_t               delta,
                      uint32_t&             out_patched,
                      uint32_t&             out_unhandled);

}
