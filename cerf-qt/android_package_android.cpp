#include "android_package.h"

#include <QtCore/qcoreapplication_platform.h>

QJniObject AndroidPackageName() {
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    return context.callObjectMethod("getPackageName", "()Ljava/lang/String;");
}

QJniObject AndroidPackageManager() {
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    return context.callObjectMethod("getPackageManager", "()Landroid/content/pm/PackageManager;");
}
