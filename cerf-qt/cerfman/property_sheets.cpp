#include "property_sheets.h"

#include "local_manifest_store.h"
#include "manager_engine.h"
#include "property_fields.h"
#include "property_sheet.h"

#include "../guest_reset_text.h"
#include "../nested_event_loops.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QEventLoop>
#include <QPointer>
#include <QQmlEngine>
#include <QVariant>

REGISTER_SERVICE(PropertySheets);

QObject* PropertySheets::CreateForDevice(const QString& name, bool running, const QString& initial_page) {
    auto* sheet = new PropertySheet(emu_, PropertySubject::OfDirectory(LocalManifestStore::DevicePath(name)),
                                    QString::fromLatin1(running ? PropertySheet::kModeLocked
                                                                : PropertySheet::kModeEdit),
                                    initial_page.isEmpty() ? QString::fromLatin1(sheet_page::kBoard) : initial_page,
                                    std::nullopt, false);
    QQmlEngine::setObjectOwnership(sheet, QQmlEngine::JavaScriptOwnership);
    return sheet;
}

bool PropertySheets::EditLive(const QVariantMap& window, const QString& device_dir, bool force_reboot,
                              std::optional<int> ce_major, cerffrontend::GuestReset& reset) {
    auto* sheet = new PropertySheet(emu_, PropertySubject::OfDirectory(device_dir),
                                    QString::fromLatin1(PropertySheet::kModeLive),
                                    QString::fromLatin1(sheet_page::kGuestAdditions), ce_major, force_reboot);
    QQmlEngine::setObjectOwnership(sheet, QQmlEngine::CppOwnership);

    bool       accepted = false;
    QString    reboot;
    QEventLoop loop;
    QObject::connect(sheet, &PropertySheet::finished, &loop,
                     [&](bool ok, const QString& answer) {
                         accepted = ok;
                         reboot   = answer;
                     });
    QVariantMap properties = window;
    properties.insert(QStringLiteral("sheet"), QVariant::fromValue<QObject*>(sheet));
    const QPointer<QObject> opened = emu_.Get<ManagerEngine>().Open(QStringLiteral("PropertiesWindow"), properties);
    QObject::connect(opened, &QObject::destroyed, &loop, &QEventLoop::quit);
    emu_.Get<NestedEventLoops>().Run(loop);
    delete opened.data();
    sheet->deleteLater();

    if (!accepted) return false;
    reset = cerffrontend::GuestResetFromValue(reboot.toStdString());
    return true;
}
