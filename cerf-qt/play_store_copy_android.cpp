#include "play_store_copy.h"

#include "android_package.h"

#include <QString>
#include <QtCore/qcoreapplication_platform.h>

namespace {

constexpr int  kInstallSourceInfoSdk = 30;
constexpr char kPlayStorePackage[]   = "com.android.vending";

QString InstallerPackage() {
    const QJniObject manager = AndroidPackageManager();
    const QJniObject name    = AndroidPackageName();
    if (QNativeInterface::QAndroidApplication::sdkVersion() < kInstallSourceInfoSdk)
        return manager
            .callObjectMethod("getInstallerPackageName", "(Ljava/lang/String;)Ljava/lang/String;",
                              name.object<jstring>())
            .toString();
    const QJniObject info = manager.callObjectMethod(
        "getInstallSourceInfo", "(Ljava/lang/String;)Landroid/content/pm/InstallSourceInfo;", name.object<jstring>());
    return info.callObjectMethod("getInstallingPackageName", "()Ljava/lang/String;").toString();
}

}

bool PlayStoreCopy() { return InstallerPackage() == QLatin1String(kPlayStorePackage); }
