#include "android_content.h"

#include <QtCore/qcoreapplication_platform.h>

#include <cerrno>

namespace {

bool IsTreeRoot(const QJniObject& uri) {
    const QJniObject segments = uri.callObjectMethod("getPathSegments", "()Ljava/util/List;");
    if (segments.callMethod<jint>("size") != 2) return false;
    const QJniObject first = segments.callObjectMethod("get", "(I)Ljava/lang/Object;", jint(0));
    return first.toString() == QLatin1String("tree");
}

}

QJniObject AndroidContentResolver() {
    const QJniObject context = QNativeInterface::QAndroidApplication::context();
    return context.callObjectMethod("getContentResolver", "()Landroid/content/ContentResolver;");
}

QJniObject AndroidUri(const QString& text) {
    return QJniObject::callStaticObjectMethod("android/net/Uri", "parse", "(Ljava/lang/String;)Landroid/net/Uri;",
                                              QJniObject::fromString(text).object<jstring>());
}

QJniObject AndroidDocumentUri(const QJniObject& uri) {
    if (!IsTreeRoot(uri)) return uri;
    const QJniObject id = QJniObject::callStaticObjectMethod(kDocumentsContractClass, "getTreeDocumentId",
                                                             "(Landroid/net/Uri;)Ljava/lang/String;", uri.object());
    return AndroidTreeDocumentUri(uri, id);
}

QJniObject AndroidTreeDocumentUri(const QJniObject& tree, const QJniObject& document_id) {
    return QJniObject::callStaticObjectMethod(kDocumentsContractClass, "buildDocumentUriUsingTree",
                                              "(Landroid/net/Uri;Ljava/lang/String;)Landroid/net/Uri;", tree.object(),
                                              document_id.object<jstring>());
}

int TakePendingJavaErrno(QJniEnvironment& env) {
    jthrowable error = env->ExceptionOccurred();
    if (error == nullptr) return 0;
    env->ExceptionClear();
    int result = EIO;
    if (env->IsInstanceOf(error, env.findClass("java/io/FileNotFoundException"))) result = ENOENT;
    else if (env->IsInstanceOf(error, env.findClass("java/lang/SecurityException"))) result = EACCES;
    env->DeleteLocalRef(error);
    return result;
}

bool JavaCallSucceeded(QJniEnvironment& env, bool produced) {
    if (const int error = TakePendingJavaErrno(env)) {
        errno = error;
        return false;
    }
    if (!produced) {
        errno = EIO;
        return false;
    }
    return true;
}
