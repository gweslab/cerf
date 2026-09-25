#include "sk_hynix_h26m52002ckr.h"

namespace {

// SK hynix 26nm 32Gb e-NAND datasheet Rev 1.1, Table 10
constexpr SdCardCid kCid = {
    0x90u,
    0x01u,
    0x4Au,
    'H', 'Y', 'N', 'I', 'X', ' ',
    0x5Du,
    0x00u, 0x00u, 0x2Du, 0x30u,
    0x2Eu,
    0x01u,
};

// SK hynix 26nm 32Gb e-NAND datasheet Rev 1.1, Table 11
constexpr EmmcCsdFields kCsd = {
    .csd_structure  = 3u,
    .spec_vers      = 4u,
    .taac           = 0x4Fu,
    .nsac           = 0x01u,
    .tran_speed     = 0x32u,
    .ccc            = 0x0F5u,
    .read_bl_len    = 9u,
    .c_size         = 0xFFFu,
    .vdd_r_curr_min = 7u,
    .vdd_r_curr_max = 7u,
    .vdd_w_curr_min = 7u,
    .vdd_w_curr_max = 7u,
    .c_size_mult    = 7u,
    .erase_grp_size = 0x1Fu,
    .erase_grp_mult = 0x1Fu,
    .wp_grp_size    = 0x1Fu,
    .wp_grp_enable  = 1u,
    .r2w_factor     = 2u,
    .write_bl_len   = 9u,
};

// SK hynix 26nm 32Gb e-NAND datasheet Rev 1.1, Table 13, 16GB column
constexpr EmmcExtCsdByte kExtCsdProperties[] = {
    {504u, 0x01u}, {503u, 0x03u}, {502u, 0x01u}, {241u, 0xDAu},
    {232u, 0x0Fu}, {231u, 0x15u}, {230u, 0x06u}, {229u, 0x09u},
    {228u, 0x07u}, {226u, 0x20u}, {225u, 0x07u}, {224u, 0x10u},
    {223u, 0x01u}, {222u, 0x08u}, {221u, 0x02u}, {220u, 0x08u},
    {219u, 0x08u}, {217u, 0x10u}, {210u, 0x08u}, {209u, 0x08u},
    {208u, 0x08u}, {207u, 0x08u}, {206u, 0x08u}, {205u, 0x08u},
    {199u, 0x01u}, {198u, 0x02u}, {196u, 0x0Fu}, {194u, 0x02u},
    {192u, 0x05u}, {168u, 0x20u}, {160u, 0x03u}, {158u, 0x01u},
    {157u, 0x9Au},
};

constexpr uint32_t kSectorCount = 0x01D74000u;

}  // namespace

SdCardCid SkHynixH26m52002ckr::Cid() const { return kCid; }

EmmcCsdFields SkHynixH26m52002ckr::Csd() const { return kCsd; }

std::span<const EmmcExtCsdByte> SkHynixH26m52002ckr::ExtCsdProperties() const {
    return kExtCsdProperties;
}

uint32_t SkHynixH26m52002ckr::SectorCount() const { return kSectorCount; }

uint8_t SkHynixH26m52002ckr::ErasedMemCont() const {
    return cerf_mmc::kErasedMemContZeros;
}
