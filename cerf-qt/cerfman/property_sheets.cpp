#include "property_sheets.h"

#include "local_manifest_store.h"
#include "manager_engine.h"
#include "property_fields.h"
#include "property_sheet.h"
#include "window_registry.h"

#include "../guest_reset_text.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>

#include <QQmlEngine>
#include <QVariant>
#include <QWindow>

#include <utility>

REGISTER_SERVICE(PropertySheets);

namespace {

constexpr char kLiveWindow[] = "PropertiesWindow";

}

QObject* PropertySheets::CreateForDevice(const QString& name, bool running, const QString& initial_page) {
    auto* sheet = new PropertySheet(emu_, PropertySubject::OfDirectory(LocalManifestStore::DevicePath(name)),
                                    QString::fromLatin1(running ? PropertySheet::kModeLocked
                                                                : PropertySheet::kModeEdit),
                                    initial_page.isEmpty() ? QString::fromLatin1(sheet_page::kBoard) : initial_page,
                                    std::nullopt, false);
    QQmlEngine::setObjectOwnership(sheet, QQmlEngine::JavaScriptOwnership);
    return sheet;
}

void PropertySheets::EditLive(const QVariantMap& window, const QString& initial_page, bool force_reboot,
                              std::optional<int> ce_major, cerffrontend::LiveSheetFinished finished) {
    const QString device = QString::fromStdString(emu_.Get<cerfcore::DeviceConfig>().device_name);
    auto*         sheet  = new PropertySheet(emu_, PropertySubject::OfDirectory(LocalManifestStore::DevicePath(device)),
                                             QString::fromLatin1(PropertySheet::kModeLive), initial_page, ce_major,
                                             force_reboot);
    QQmlEngine::setObjectOwnership(sheet, QQmlEngine::CppOwnership);
    QObject::connect(sheet, &PropertySheet::finished, sheet,
                     [finished = std::move(finished)](bool accepted, const QString& answer) {
                         finished(accepted, cerffrontend::GuestResetFromValue(answer.toStdString()));
                     });
    QVariantMap properties = window;
    properties.insert(QStringLiteral("sheet"), QVariant::fromValue<QObject*>(sheet));
    auto* opened =
        qobject_cast<QWindow*>(emu_.Get<ManagerEngine>().Open(QString::fromLatin1(kLiveWindow), properties));
    sheet->setParent(opened);
    emu_.Get<WindowRegistry>().Track(QString::fromLatin1(kLiveWindow), opened);
}

bool PropertySheets::ShowLive(const QString& page, bool force_reboot) {
    QWindow* shown = emu_.Get<WindowRegistry>().Raise(QString::fromLatin1(kLiveWindow));
    if (shown == nullptr) return false;
    qobject_cast<PropertySheet*>(shown->property("sheet").value<QObject*>())->Request(page, force_reboot);
    return true;
}
