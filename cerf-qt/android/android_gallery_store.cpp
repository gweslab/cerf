#include "../screenshot_store.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>

#include <QJniEnvironment>
#include <QJniObject>
#include <QString>
#include <QtCore/qcoreapplication_platform.h>

namespace {

constexpr char kGallerySaverClass[] = "cx/cerf/GallerySaver";

class AndroidGalleryStore : public cerffrontend::ScreenshotStore {
public:
    using cerffrontend::ScreenshotStore::ScreenshotStore;

    bool Store(const std::vector<uint8_t>& png, const std::string& file_name) override {
        QJniEnvironment  env;
        const jsize      size  = static_cast<jsize>(png.size());
        const jbyteArray bytes = env->NewByteArray(size);
        env->SetByteArrayRegion(bytes, 0, size, reinterpret_cast<const jbyte*>(png.data()));
        const QJniObject context = QNativeInterface::QAndroidApplication::context();
        const QJniObject name    = QJniObject::fromString(QString::fromStdString(file_name));
        const QJniObject failure = QJniObject::callStaticObjectMethod(
            kGallerySaverClass, "savePng", "(Landroid/content/Context;Ljava/lang/String;[B)Ljava/lang/String;",
            context.object(), name.object<jstring>(), bytes);
        env->DeleteLocalRef(bytes);
        if (env.checkAndClearExceptions()) {
            LOG(Caution, "AndroidGalleryStore: %s threw\n", file_name.c_str());
            return false;
        }
        if (failure.isValid()) {
            LOG(Caution, "AndroidGalleryStore: %s not saved: %s\n", file_name.c_str(),
                qUtf8Printable(failure.toString()));
            return false;
        }
        return true;
    }
};

}

REGISTER_SERVICE_AS(AndroidGalleryStore, cerffrontend::ScreenshotStore);
