#include "file_offer.h"

#include "device_file_value.h"
#include "filesystem_path.h"

#include "../android/android_content.h"
#include "../android_package.h"

#include <QJniEnvironment>
#include <QJniObject>
#include <QtCore/qcoreapplication_platform.h>

namespace {

constexpr char kIntentClass[] = "android/content/Intent";

QJniObject IntentString(const char* field) { return QJniObject::getStaticObjectField<jstring>(kIntentClass, field); }

QJniObject ProvidedUri(const QJniObject& context, const QString& absolute_path) {
    const QJniObject package = AndroidPackageName();
    const QJniObject file("java/io/File", "(Ljava/lang/String;)V",
                          QJniObject::fromString(absolute_path).object<jstring>());
    return QJniObject::callStaticObjectMethod(
        "androidx/core/content/FileProvider", "getUriForFile",
        "(Landroid/content/Context;Ljava/lang/String;Ljava/io/File;)Landroid/net/Uri;", context.object(),
        QJniObject::fromString(package.toString() + QStringLiteral(".qtprovider")).object<jstring>(), file.object());
}

}

bool OfferFile(const QString& path, const QString& mime_type) {
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    const QJniObject uri     = IsDocumentFileValue(path) ? AndroidUri(path) : ProvidedUri(context, path);
    if (!uri.isValid()) return false;
    const QJniObject send(kIntentClass, "(Ljava/lang/String;)V", IntentString("ACTION_SEND").object<jstring>());
    send.callObjectMethod("setType", "(Ljava/lang/String;)Landroid/content/Intent;",
                          QJniObject::fromString(mime_type).object<jstring>());
    send.callObjectMethod("putExtra", "(Ljava/lang/String;Landroid/os/Parcelable;)Landroid/content/Intent;",
                          IntentString("EXTRA_STREAM").object<jstring>(), uri.object());
    const QJniObject clip = QJniObject::callStaticObjectMethod(
        "android/content/ClipData", "newUri",
        "(Landroid/content/ContentResolver;Ljava/lang/CharSequence;Landroid/net/Uri;)Landroid/content/ClipData;",
        AndroidContentResolver().object(), QJniObject::fromString(PathDisplayName(path)).object<jstring>(),
        uri.object());
    send.callMethod<void>("setClipData", "(Landroid/content/ClipData;)V", clip.object());
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
