#pragma once

#include <cstdint>
#include <vector>

class PeImage {
public:
    struct Section {
        uint32_t vsize        = 0;  /* IMAGE_SECTION_HEADER.VirtualSize    */
        uint32_t rva          = 0;  /* IMAGE_SECTION_HEADER.VirtualAddress */
        uint32_t psize        = 0;  /* IMAGE_SECTION_HEADER.SizeOfRawData  */
        uint32_t pe_file_off  = 0;  /* IMAGE_SECTION_HEADER.PointerToRawData */
        uint32_t flags        = 0;  /* IMAGE_SECTION_HEADER.Characteristics */
    };

    explicit PeImage(std::vector<uint8_t> pe_bytes);

    bool                          Parsed()       const { return parsed_; }
    const std::vector<uint8_t>&   Bytes()        const { return pe_bytes_; }

    uint32_t EntryRva()       const { return entry_rva_; }
    uint16_t Machine()        const { return machine_; }
    uint32_t ImageBase()      const { return image_base_; }
    uint32_t ImageSize()      const { return image_size_; }
    uint32_t StackReserve()   const { return stack_reserve_; }
    uint16_t Subsystem()      const { return subsystem_; }
    uint16_t SubsysMajor()    const { return subsys_major_; }
    uint16_t SubsysMinor()    const { return subsys_minor_; }
    uint16_t ImageFlags()     const { return image_flags_; }

    /* PE Optional Header DataDirectory[i] — fed into e32_rom's
       e32_unit[i] (i ∈ [0..8]) when building the ROM module record.
       Index out of range returns zeroes. */
    uint32_t DirRva (int i)   const { return (i >= 0 && i < 16) ? dirs_[i].rva  : 0; }
    uint32_t DirSize(int i)   const { return (i >= 0 && i < 16) ? dirs_[i].size : 0; }

    const std::vector<Section>& Sections() const { return sections_; }

private:
    struct Directory { uint32_t rva = 0; uint32_t size = 0; };

    std::vector<uint8_t>  pe_bytes_;
    bool                  parsed_        = false;
    uint16_t              machine_       = 0;
    uint32_t              entry_rva_     = 0;
    uint32_t              image_base_    = 0;
    uint32_t              image_size_    = 0;
    uint32_t              stack_reserve_ = 0;
    uint16_t              subsystem_     = 0;
    uint16_t              subsys_major_  = 0;
    uint16_t              subsys_minor_  = 0;
    uint16_t              image_flags_   = 0;
    Directory             dirs_[16]{};
    std::vector<Section>  sections_;
};
