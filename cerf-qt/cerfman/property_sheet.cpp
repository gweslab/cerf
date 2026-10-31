#include "property_sheet.h"

#include "board_catalog.h"
#include "cpu_config_catalog.h"
#include "device_form_rules.h"
#include "persisted_options.h"
#include "property_options.h"
#include "property_preview.h"

#include "../CerfStyle/touch_frontend.h"

#include "../guest_reset_text.h"
#include "../qt_qml_value.h"

#include <cerfcore/core/board_database.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cpu_config_database.h>
#include <cerfcore/core/product_name.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_framebuffer.h>

#include <array>
#include <optional>

namespace {

namespace pf = persist_field;
namespace sf = sheet_field;
namespace sp = sheet_page;

constexpr std::array<const char*, 12> kLiveKeys = {
    pf::kGuestAdditions, pf::kShareFolder, pf::kMountPoint, pf::kWidth,       pf::kHeight,      pf::kBpp,
    pf::kDpi,            pf::kFontSize,    pf::kClearType,  pf::kColorScheme, pf::kAllowUntrustedApps, pf::kHud};
constexpr std::array<const char*, 4> kRebootKeys      = {pf::kBpp, pf::kDpi, pf::kFontSize, pf::kColorScheme};
constexpr std::array<const char*, 2> kLiveResizeKeys  = {pf::kWidth, pf::kHeight};
constexpr int                        kLiveResizeMinCe = 4;

Json FilesToJson(const FileValues& files) {
    Json out = Json::object();
    for (auto it = files.constBegin(); it != files.constEnd(); ++it)
        out[it.key().toStdString()] = it.value().toStdString();
    return out;
}

FileValues JsonToFiles(const Json& object) {
    FileValues out;
    for (const auto& [key, value] : object.items())
        out.insert(QString::fromStdString(key), JsonString(value));
    return out;
}

}

PropertySubject PropertySubject::OfDirectory(const QString& path) {
    DeviceDirectory      device(path);
    const ParsedCerfJson parsed       = device.ReadMeta();
    QString              display_name = parsed.meta.DisplayNameOr(device.Name());
    return PropertySubject{std::move(device),         std::move(display_name),
                           parsed.meta.os_ver_major,   parsed.meta.forbid_guest_additions,
                           parsed.width,               parsed.height};
}

PropertySheet::PropertySheet(cerfcore::CerfEmulator& emu, PropertySubject subject, QString mode,
                             QString initial_page, std::optional<int> ce_major, bool force_reboot,
                             QObject* parent)
    : QObject(parent),
      emu_(emu),
      subject_(std::move(subject)),
      mode_(std::move(mode)),
      initial_page_(std::move(initial_page)),
      ce_major_(ce_major),
      force_reboot_(force_reboot) {
    const PersistedValues persisted = ReadPersistedValues(subject_.device, MountPointDefault());
    baseline_               = persisted.baseline;
    values_                 = persisted.values;
    values_[sf::kBoardId]   = subject_.device.BoardId().toStdString();
    const DeviceFiles files = subject_.device.ReadFiles();
    values_[sf::kRom]       = FilesToJson(files.rom);
    values_[sf::kStorage]   = FilesToJson(files.storage);
    values_[sf::kName]      = subject_.display_name.toStdString();
    initial_                = values_;
    if (Live()) values_[pf::kGuestAdditions] = true;
}

bool PropertySheet::FullScreenSetting() const { return !TouchFrontend::Active(); }

bool PropertySheet::DoubleTapHelperSetting() const { return TouchFrontend::Active(); }

QString PropertySheet::MountPointDefault() const { return emu_.Get<BoardCatalog>().MountPointDefault(); }

QVariantMap PropertySheet::Problem() const {
    const auto failure = [](const char* page, const QString& title, const QString& message) {
        return QVariantMap{{QStringLiteral("page"), QString::fromLatin1(page)},
                           {QStringLiteral("title"), title},
                           {QStringLiteral("message"), message}};
    };
    if (Editable()) {
        const QString     rom     = QString::fromLatin1(sf::kRom);
        const QString     storage = QString::fromLatin1(sf::kStorage);
        const QVariantMap values  = Values();
        const QVariantMap files{{rom, values.value(rom)}, {storage, values.value(storage)}};
        const QString reason =
            emu_.Get<DeviceFormRules>().Problem(BoardId(), files, subject_.device.Path());
        if (!reason.isEmpty())
            return failure(sp::kBoard, QStringLiteral("Board Settings"), reason);
    }
    if (GuestAdditionsOn()) {
        auto& options = emu_.Get<PropertyOptions>();
        if (!options.MountPointValid(JsonText(values_, pf::kMountPoint).trimmed()))
            return failure(sp::kGuestAdditions, QStringLiteral("Invalid mount point"),
                           options.MountPointInvalidMessage());
        if (!ScreenFits())
            return failure(sp::kGuestAdditions, QStringLiteral("Display resolution"),
                           QStringLiteral("Guest Additions cannot hold this resolution at this "
                                          "color depth."));
    }
    return {};
}

bool PropertySheet::ScreenFits() const {
    const QVariantList size = Resolution().toList();
    if (size.size() != 2) return true;
    const uint32_t w   = size.at(0).toUInt();
    const uint32_t h   = size.at(1).toUInt();
    const uint32_t bpp = uint32_t(JsonInteger(values_, pf::kBpp).value_or(AutoDepth()));
    if (Live()) return emu_.Get<cerfcore::CerfVirtFramebuffer>().CanApply(w, h, bpp);
    using cerfcore::CerfVirtFramebuffer;
    return CerfVirtFramebuffer::PrimaryBytesAt(w, h, bpp) <=
           CerfVirtFramebuffer::RegionBytesIn(emu_.Get<BoardCatalog>().GaWindowSize(BoardId()));
}

bool PropertySheet::Flag(const char* key) const { return values_.at(key).get<bool>(); }

bool PropertySheet::GuestAdditionsOn() const {
    return Flag(pf::kGuestAdditions) && GuestAdditionsAvailable(BoardId());
}

bool PropertySheet::FullScreen() const { return Flag(pf::kFullScreen); }

bool PropertySheet::NetworkEnabled() const { return Flag(pf::kNetworkEnabled); }

bool PropertySheet::DoubleTapHelper() const { return Flag(cerfcore::config_key::kDoubleTapHelper); }

QVariant PropertySheet::Hud() const { return values_.contains(pf::kHud) ? QVariant(JsonText(values_, pf::kHud)) : NullVariant(); }

bool PropertySheet::AllowUntrustedApps() const { return Flag(pf::kAllowUntrustedApps); }

QString PropertySheet::Title() const {
    return QStringLiteral("%1 - Properties").arg(subject_.display_name);
}

QVariantMap PropertySheet::Values() const {
    QVariantMap out = JsonToVariant(values_).toMap();
    for (const char* key : kPersistKeys)
        if (!values_.contains(key)) out.insert(QString::fromLatin1(key), NullVariant());
    return out;
}

QString PropertySheet::BoardId() const { return JsonText(values_, sf::kBoardId); }

QVariant PropertySheet::Resolution() const {
    if (!values_.contains(pf::kWidth) || !values_.contains(pf::kHeight)) return NullVariant();
    return QVariantList{JsonToVariant(values_[pf::kWidth]), JsonToVariant(values_[pf::kHeight])};
}

QString PropertySheet::ShareFolder() const { return JsonText(values_, pf::kShareFolder); }

QString PropertySheet::MountPoint() const { return JsonText(values_, pf::kMountPoint); }

Json PropertySheet::BoardCpuOverrideJson() const {
    Json       overrides = Json::object();
    const auto cpu       = values_.find(pf::kCpuConfig);
    if (cpu == values_.end()) return overrides;
    for (const cerfcore::CpuConfigParam* param : emu_.Get<CpuConfigCatalog>().ParamsFor(BoardId()))
        if (cpu->contains(param->id)) overrides[param->id] = (*cpu)[param->id];
    return overrides;
}

QVariantMap PropertySheet::BoardCpuOverrides() const { return JsonToVariant(BoardCpuOverrideJson()).toMap(); }

QVariantMap PropertySheet::CpuOverrides() const {
    const QVariantMap overrides = BoardCpuOverrides();
    QVariantMap       out;
    for (const cerfcore::CpuConfigParam* param : emu_.Get<CpuConfigCatalog>().ParamsFor(BoardId())) {
        const QString id = QString::fromStdString(param->id);
        out.insert(id, overrides.contains(id) ? overrides.value(id) : NullVariant());
    }
    return out;
}

QVariant PropertySheet::CpuPreset() const {
    return emu_.Get<CpuConfigCatalog>().CurrentPreset(BoardId(), BoardCpuOverrides());
}

QVariantList PropertySheet::ResetChoices() const {
    const auto choice = [](const char* value, const char* label) {
        return QVariantMap{{QStringLiteral("value"), QString::fromLatin1(value)},
                           {QStringLiteral("label"), QString::fromLatin1(label)}};
    };
    return {choice(cerffrontend::kNoResetValue, "Do not reset"), choice(cerffrontend::kSoftResetValue, "Soft reset"),
            choice(cerffrontend::kHardResetValue, "Hard reset")};
}

QString PropertySheet::NoReset() const { return QString::fromLatin1(cerffrontend::kNoResetValue); }

QString PropertySheet::SoftReset() const { return QString::fromLatin1(cerffrontend::kSoftResetValue); }

bool PropertySheet::GuestAdditionsAvailable(const QString& board_id) const {
    if (subject_.forbid_guest_additions || subject_.os_ver_major == 1) return false;
    return emu_.Get<BoardCatalog>().FeatureAllowed(board_id, "guest_additions");
}

QVariantList PropertySheet::Pages() const {
    const QString board_id = BoardId();
    auto&         catalog  = emu_.Get<BoardCatalog>();
    QVariantList  pages;
    const auto add = [&pages](const char* key, const QString& title) {
        pages.append(QVariantMap{{QStringLiteral("key"), QString::fromLatin1(key)}, {QStringLiteral("title"), title}});
    };
    add(sp::kBoard, QStringLiteral("Board Settings"));
    if (GuestAdditionsAvailable(board_id)) add(sp::kGuestAdditions, QStringLiteral("Guest Additions"));
    if (catalog.ConfigurableScreen(board_id) && !GuestAdditionsOn()) add(sp::kDisplay, QStringLiteral("Display"));
    if (catalog.Find(board_id)) add(sp::kCpuConfig, QStringLiteral("CPU Configuration"));
    add(sp::kEmulator, QStringLiteral("Emulator Settings"));
    return pages;
}

QVariantList PropertySheet::Preview() const { return emu_.Get<PropertyPreview>().Blocks(*this); }

QSize PropertySheet::AutoSize() const {
    return AutoResolution(subject_.default_width, subject_.default_height,
                          emu_.Get<BoardCatalog>().PanelSize(BoardId()));
}

int PropertySheet::AutoDepth() const { return emu_.Get<BoardCatalog>().GaColorDepth(BoardId()); }

bool PropertySheet::RebootRequired() const {
    if (!Live()) return false;
    const auto changed = [this](const char* key) {
        return ValueOrNull(values_, key) != ValueOrNull(initial_, key);
    };
    for (const char* key : kRebootKeys)
        if (changed(key)) return true;
    if (ce_major_ && *ce_major_ >= kLiveResizeMinCe) return false;
    for (const char* key : kLiveResizeKeys)
        if (changed(key)) return true;
    return false;
}

void PropertySheet::SetValue(const QString& key, const QVariant& value) {
    values_[key.toStdString()] = VariantToJson(value);
    emit valuesChanged();
}

void PropertySheet::ClearValue(const QString& key) {
    values_.erase(key.toStdString());
    emit valuesChanged();
}

void PropertySheet::SetOrClear(const QString& key, const QVariant& value) {
    if (value.isNull()) ClearValue(key);
    else                SetValue(key, value);
}

void PropertySheet::SetResolution(const QVariant& size) {
    const QVariantList pair = PlainQmlValue(size).toList();
    if (pair.size() == 2) {
        values_[pf::kWidth]  = VariantToJson(pair.at(0));
        values_[pf::kHeight] = VariantToJson(pair.at(1));
    } else {
        values_.erase(pf::kWidth);
        values_.erase(pf::kHeight);
    }
    emit valuesChanged();
}

QVariantList PropertySheet::ResolutionForPrompt() const {
    const QVariant set = Resolution();
    if (!set.isNull()) return set.toList();
    const QSize size = AutoSize();
    return {size.width(), size.height()};
}

int PropertySheet::DpiForPrompt() const {
    return int(JsonInteger(values_, pf::kDpi).value_or(emu_.Get<PropertyOptions>().DefaultDpi()));
}

void PropertySheet::ApplyScalePreset(int index) {
    const ScaleSetting preset = emu_.Get<PropertyOptions>().ScalePresetAt(index);
    values_[pf::kDpi]       = preset.dpi;
    values_[pf::kFontSize]  = preset.font_size;
    values_[pf::kClearType] = preset.cleartype;
    emit valuesChanged();
}

void PropertySheet::SetMountPoint(const QString& name) {
    values_[pf::kMountPoint] = EffectiveMountPoint(name, MountPointDefault()).toStdString();
    emit valuesChanged();
}

void PropertySheet::SetCpuOverride(const QString& param_id, const QVariant& value) {
    Json overrides = BoardCpuOverrideJson();
    if (value.isNull()) overrides.erase(param_id.toStdString());
    else                overrides[param_id.toStdString()] = VariantToJson(value);
    values_[pf::kCpuConfig] = overrides;
    emit valuesChanged();
}

void PropertySheet::ApplyCpuPreset(const QVariant& choice) {
    values_[pf::kCpuConfig] =
        choice.isNull() ? Json::object()
                        : VariantToJson(emu_.Get<CpuConfigCatalog>().PresetValues(BoardId(), choice.toInt()));
    emit valuesChanged();
}

QString PropertySheet::SaveOwned(bool all) {
    Json          values   = values_;
    const QString board_id = BoardId();
    if (!GuestAdditionsAvailable(board_id)) values[pf::kGuestAdditions] = false;
    values[pf::kCpuConfig] = BoardCpuOverrideJson();

    QString error;
    if (all) {
        if (!subject_.device.WriteBoardFileOverrides(board_id, JsonToFiles(values[sf::kRom]),
                                                     JsonToFiles(values[sf::kStorage]), error))
            return error;
        if (values[sf::kName] != initial_[sf::kName] &&
            !subject_.device.WriteUserName(JsonText(values, sf::kName), error))
            return error;
        if (!PersistSubset(subject_.device, baseline_, kPersistKeys, values, error)) return error;
        return QString();
    }
    if (!PersistSubset(subject_.device, baseline_, kLiveKeys, values, error)) return error;
    return QString();
}

QString PropertySheet::Save() { return SaveOwned(Editable()); }

void PropertySheet::Finish(const QString& reboot) { emit finished(true, reboot); }

void PropertySheet::Cancel() { emit finished(false, QString()); }
