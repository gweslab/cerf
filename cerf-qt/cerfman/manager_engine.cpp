#include "manager_engine.h"

#include "manager_qml_engine.h"
#include "asset_image_provider.h"
#include "svg_icon_provider.h"
#include "../CerfStyle/legacy_windows.h"
#include "../CerfStyle/touch_frontend.h"
#include "../resource_paths_text.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/fatal.h>

#include <QQmlComponent>
#include <QQuickWindow>
#include <QSGRendererInterface>
#include <QtQml/qqmlextensionplugin.h>

#include <algorithm>

Q_IMPORT_QML_PLUGIN(CerfStylePlugin)

REGISTER_SERVICE(ManagerEngine);

namespace {

void ConfigureQuick() {
    constexpr char kMaterialVariantVar[] = "QT_QUICK_CONTROLS_MATERIAL_VARIANT";
    if (!TouchFrontend::Active() && !qEnvironmentVariableIsSet(kMaterialVariantVar))
        qputenv(kMaterialVariantVar, "Dense");
    if (LegacyWindows::Active()) QQuickWindow::setGraphicsApi(QSGRendererInterface::OpenGL);
}

}

ManagerEngine::~ManagerEngine() = default;

void ManagerEngine::OnShutdown() {
    for (QPointer<QObject>& object : opened_) delete object.data();
    opened_.clear();
    engine_.reset();
}

ManagerQmlEngine& ManagerEngine::Engine() {
    if (!engine_) {
        ConfigureQuick();
        engine_ = std::make_unique<ManagerQmlEngine>(emu_);
        engine_->addImageProvider(QStringLiteral(CERF_SYMBOL_IMAGE_PROVIDER), new SvgIconProvider);
        engine_->addImageProvider(QStringLiteral(CERF_ASSET_IMAGE_PROVIDER), new AssetImageProvider);
    }
    return *engine_;
}

QObject* ManagerEngine::Open(const QString& type_name, const QVariantMap& properties) {
    QQmlComponent component(&Engine(), QStringLiteral(CERF_MANAGER_QML_MODULE), type_name);
    QObject*      object = component.createWithInitialProperties(properties);
    if (object == nullptr)
        emu_.Get<cerfcore::Fatal>().Die("ManagerEngine: %s did not load: %s",
                                        qUtf8Printable(type_name),
                                        qUtf8Printable(component.errorString()));
    opened_.erase(std::remove_if(opened_.begin(), opened_.end(),
                                 [](const QPointer<QObject>& p) { return p.isNull(); }),
                  opened_.end());
    opened_.emplace_back(object);
    return object;
}
