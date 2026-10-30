#include "pc_key_legend.h"

#include <algorithm>
#include <cctype>

namespace cerffrontend {

namespace {

struct KeyLegend {
    uint8_t     vk;
    const char* legend;
};

constexpr KeyLegend kPcKeys[] = {
    {0x1B, "Esc"},  {0x70, "F1"},   {0x71, "F2"},   {0x72, "F3"},   {0x73, "F4"},   {0x74, "F5"},
    {0x75, "F6"},   {0x76, "F7"},   {0x77, "F8"},   {0x78, "F9"},   {0x79, "F10"},  {0x7A, "F11"},
    {0x7B, "F12"},  {0xC0, "`"},    {0x31, "1"},    {0x32, "2"},    {0x33, "3"},    {0x34, "4"},
    {0x35, "5"},    {0x36, "6"},    {0x37, "7"},    {0x38, "8"},    {0x39, "9"},    {0x30, "0"},
    {0xBD, "-"},    {0xBB, "="},    {0x08, "Bksp"}, {0x09, "Tab"},  {0x51, "Q"},    {0x57, "W"},
    {0x45, "E"},    {0x52, "R"},    {0x54, "T"},    {0x59, "Y"},    {0x55, "U"},    {0x49, "I"},
    {0x4F, "O"},    {0x50, "P"},    {0xDB, "["},    {0xDD, "]"},    {0xDC, "\\"},   {0x14, "Caps"},
    {0x41, "A"},    {0x53, "S"},    {0x44, "D"},    {0x46, "F"},    {0x47, "G"},    {0x48, "H"},
    {0x4A, "J"},    {0x4B, "K"},    {0x4C, "L"},    {0xBA, ";"},    {0xDE, "'"},    {0x0D, "Enter"},
    {0x10, "Shift"}, {0x5A, "Z"},   {0x58, "X"},    {0x43, "C"},    {0x56, "V"},    {0x42, "B"},
    {0x4E, "N"},    {0x4D, "M"},    {0xBC, ","},    {0xBE, "."},    {0xBF, "/"},    {0x11, "Ctrl"},
    {0x5B, "Win"},  {0x12, "Alt"},  {0x20, "Space"}, {0x5C, "Win"}, {0x5D, "Menu"}, {0x2D, "Ins"},
    {0x24, "Home"}, {0x21, "PgUp"}, {0x2E, "Del"},  {0x23, "End"},  {0x22, "PgDn"},
    {0x26, "\xE2\x86\x91"}, {0x25, "\xE2\x86\x90"}, {0x28, "\xE2\x86\x93"}, {0x27, "\xE2\x86\x92"},
};

}

const char* PcKeyLegend(uint8_t vk) {
    for (const KeyLegend& key : kPcKeys)
        if (key.vk == vk) return key.legend;
    return nullptr;
}

bool PcLegendKey(std::string_view legend, uint8_t& vk) {
    for (const KeyLegend& key : kPcKeys) {
        if (legend != key.legend) continue;
        vk = key.vk;
        return true;
    }
    return false;
}

bool SameKeyName(std::string_view a, std::string_view b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
               return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
           });
}

}
