/* Dialog template helpers — shared between dialog.cpp and dialog_template.cpp */
#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include "../win32_thunks.h"

struct DlgFixupResult {
    bool had_captionok;
    bool is_child;
    uint32_t wce_style;
    uint32_t wce_exstyle;
};

uint32_t ComputeDlgTemplateSize(EmulatedMemory& mem, uint32_t addr);
std::vector<uint8_t> CopyDlgTemplate(EmulatedMemory& mem, uint32_t addr);
DlgFixupResult FixupDlgTemplate(std::vector<uint8_t>& tmpl, const std::wstring& sysfont_name);
