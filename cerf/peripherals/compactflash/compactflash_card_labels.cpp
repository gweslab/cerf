#include "compactflash_card.h"

#include "../../core/cerf_emulator.h"
#include "../../core/string_utils.h"
#include "../../host/ui_language.h"

#include <filesystem>

std::wstring CompactFlashCard::ImageName() const {
    return std::filesystem::path(image_path_).filename().wstring();
}

std::wstring CompactFlashCard::DisplayName() const {
    return L"CompactFlash (" + ImageName() + L")";
}

std::wstring CompactFlashCard::MenuLabel() const {
    return emu_.Get<UiLanguage>().Format("pcmcia.cf.image_name",
        {{"name", WideToUtf8(ImageName())}});
}

std::wstring CompactFlashCard::TooltipDetail() const {
    const auto label = MenuLabel();
    if (!file_) {
        return label + L" - " + emu_.Get<UiLanguage>().Text("pcmcia.cf.image_missing");
    }
    return label + L" - " + std::to_wstring(total_sectors_ / 2048u) + L" MB";
}
