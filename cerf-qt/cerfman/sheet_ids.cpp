#include "sheet_ids.h"

#include "property_fields.h"
#include "settings_pages.h"

#include <cerfcore/core/device_config_keys.h>

QString SheetIds::BoardId() const { return QString::fromLatin1(sheet_field::kBoardId); }
QString SheetIds::Name() const { return QString::fromLatin1(sheet_field::kName); }
QString SheetIds::Rom() const { return QString::fromLatin1(sheet_field::kRom); }
QString SheetIds::Storage() const { return QString::fromLatin1(sheet_field::kStorage); }
QString SheetIds::GuestAdditions() const { return QString::fromLatin1(persist_field::kGuestAdditions); }
QString SheetIds::NetworkEnabled() const { return QString::fromLatin1(persist_field::kNetworkEnabled); }
QString SheetIds::ColorScheme() const { return QString::fromLatin1(persist_field::kColorScheme); }
QString SheetIds::FullScreen() const { return QString::fromLatin1(persist_field::kFullScreen); }
QString SheetIds::Dpi() const { return QString::fromLatin1(persist_field::kDpi); }
QString SheetIds::FontSize() const { return QString::fromLatin1(persist_field::kFontSize); }
QString SheetIds::ClearType() const { return QString::fromLatin1(persist_field::kClearType); }
QString SheetIds::AllowUntrustedApps() const { return QString::fromLatin1(persist_field::kAllowUntrustedApps); }
QString SheetIds::Bpp() const { return QString::fromLatin1(persist_field::kBpp); }
QString SheetIds::ShareFolder() const { return QString::fromLatin1(persist_field::kShareFolder); }
QString SheetIds::ThrottleMultiplier() const { return QString::fromLatin1(cerfcore::config_key::kThrottleMultiplier); }
QString SheetIds::CpuRateMultiplier() const { return QString::fromLatin1(cerfcore::config_key::kCpuRateMultiplier); }
QString SheetIds::DoubleTapHelper() const { return QString::fromLatin1(cerfcore::config_key::kDoubleTapHelper); }
QString SheetIds::BoardPage() const { return QString::fromLatin1(sheet_page::kBoard); }
QString SheetIds::GuestAdditionsPage() const { return QString::fromLatin1(sheet_page::kGuestAdditions); }
QString SheetIds::DisplayPage() const { return QString::fromLatin1(sheet_page::kDisplay); }
QString SheetIds::CpuConfigPage() const { return QString::fromLatin1(sheet_page::kCpuConfig); }
QString SheetIds::EmulatorPage() const { return QString::fromLatin1(sheet_page::kEmulator); }
QString SheetIds::SettingsEmulatorPage() const { return QString::fromLatin1(settings_page::kEmulator); }
QString SheetIds::SettingsTutorialPage() const { return QString::fromLatin1(settings_page::kTutorial); }
QString SheetIds::SettingsFeedbackPage() const { return QString::fromLatin1(settings_page::kFeedback); }
QString SheetIds::SettingsAboutPage() const { return QString::fromLatin1(settings_page::kAbout); }
