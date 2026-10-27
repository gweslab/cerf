#include "picked_document.h"

#include "../mobile/android_content.h"

#include <cerfcore/core/log.h>

namespace {

constexpr char kIntentClass[] = "android/content/Intent";

bool TakeGrant(const QJniObject& uri, jint flags) {
    QJniEnvironment  env;
    const QJniObject resolver = AndroidContentResolver();
    const jmethodID  take     = env.findMethod(env.findClass(kContentResolverClass), "takePersistableUriPermission",
                                               "(Landroid/net/Uri;I)V");
    env->CallVoidMethod(resolver.object(), take, uri.object(), flags);
    return TakePendingJavaErrno(env) == 0;
}

}

QString AdoptPickedDocument(const QUrl& url) {
    const QString    text  = url.toString();
    const QJniObject uri   = AndroidUri(text);
    const jint       read  = QJniObject::getStaticField<jint>(kIntentClass, "FLAG_GRANT_READ_URI_PERMISSION");
    const jint       write = QJniObject::getStaticField<jint>(kIntentClass, "FLAG_GRANT_WRITE_URI_PERMISSION");
    if (!TakeGrant(uri, read | write) && !TakeGrant(uri, read))
        LOG(Caution, "FileAccess: %s has no persistable grant; it opens only until CERF restarts\n",
            qUtf8Printable(text));
    return text;
}
