#include "file_offer.h"

#include <QJniEnvironment>
#include <QJniObject>
#include <QtCore/qcoreapplication_platform.h>

namespace {

constexpr char kIntentClass[] = "android/content/Intent";

QJniObject IntentString(const char* field) { return QJniObject::getStaticObjectField<jstring>(kIntentClass, field); }

}

bool OfferFile(const QString& absolute_path) {
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    const QJniObject package = context.callObjectMethod("getPackageName", "()Ljava/lang/String;");
    const QJniObject file("java/io/File", "(Ljava/lang/String;)V",
                          QJniObject::fromString(absolute_path).object<jstring>());
    const QJniObject uri = QJniObject::callStaticObjectMethod(
        "androidx/core/content/FileProvider", "getUriForFile",
        "(Landroid/content/Context;Ljava/lang/String;Ljava/io/File;)Landroid/net/Uri;", context.object(),
        QJniObject::fromString(package.toString() + QStringLiteral(".qtprovider")).object<jstring>(), file.object());
    if (!uri.isValid()) return false;
    const QJniObject send(kIntentClass, "(Ljava/lang/String;)V", IntentString("ACTION_SEND").object<jstring>());
    send.callObjectMethod("setType", "(Ljava/lang/String;)Landroid/content/Intent;",
                          QJniObject::fromString(QStringLiteral("text/plain")).object<jstring>());
    send.callObjectMethod("putExtra", "(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;",
                          IntentString("EXTRA_STREAM").object<jstring>(), uri.object());
    send.callObjectMethod("addFlags", "(I)Landroid/content/Intent;",
                          QJniObject::getStaticField<jint>(kIntentClass, "FLAG_GRANT_READ_URI_PERMISSION"));
    const QJniObject chooser = QJniObject::callStaticObjectMethod(
        kIntentClass, "createChooser", "(Landroid/content/Intent;Ljava/lang/CharSequence;)Landroid/content/Intent;",
        send.object(), static_cast<jobject>(nullptr));
    QJniEnvironment env;
    env->CallVoidMethod(context.object(),
                        env.findMethod(context.objectClass(), "startActivity", "(Landroid/content/Intent;)V"),
                        chooser.object());
    return !env.checkAndClearExceptions();
}
