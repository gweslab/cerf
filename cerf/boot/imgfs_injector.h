#pragma once

#include "../core/service.h"

#include <cstdint>
#include <string>
#include <vector>

class ImgfsInjector : public Service {
public:
    using Service::Service;
    bool ShouldRegister() override;
    void OnReady() override;

    /* Try to replace one IMGFS-resident module with cerf_guest.dll
       loaded from `source_path`. Returns true on successful patch;
       false if victim isn't in IMGFS at all. Halts on any failure
       after the victim is found. */
    bool ReplaceVictim(const char* victim_name,
                       const std::string& source_path);

private:
    struct FreeFtlSlot {
        uint32_t block_idx;
        uint32_t entry_idx;
        uint32_t phys_page_idx;
    };

    uint32_t flash_pa_base_  = 0;
    bool     flash_anchored_ = false;
    uint32_t ce_major_       = 5;
    std::vector<FreeFtlSlot> free_ftl_slots_;
    uint32_t                 next_new_ls_   = 0;
};
