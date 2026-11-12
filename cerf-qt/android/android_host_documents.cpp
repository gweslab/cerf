#include <cerfcore/platform/host_documents.h>

#include "android_content.h"

#include <cerrno>
#include <initializer_list>
#include <iterator>
#include <vector>

namespace {

constexpr char kDocument[]    = "android/provider/DocumentsContract$Document";
constexpr char kOctetStream[] = "application/octet-stream";

enum ColumnSlot { kIdColumn, kNameColumn, kMimeColumn, kSizeColumn, kModifiedColumn, kFlagsColumn };

constexpr const char* kColumns[] = {"COLUMN_DOCUMENT_ID", "COLUMN_DISPLAY_NAME", "COLUMN_MIME_TYPE",
                                    "COLUMN_SIZE",        "COLUMN_LAST_MODIFIED", "COLUMN_FLAGS"};

QJniObject DocumentConstant(const char* field) {
    return QJniObject::getStaticObjectField(kDocument, field, "Ljava/lang/String;");
}

QJniObject DirectoryMimeType() { return DocumentConstant("MIME_TYPE_DIR"); }

jint ColumnIndex(const QJniObject& cursor, const char* field) {
    return cursor.callMethod<jint>("getColumnIndex", "(Ljava/lang/String;)I", DocumentConstant(field).object<jstring>());
}

bool HasValue(const QJniObject& cursor, jint index) {
    return index >= 0 && !cursor.callMethod<jboolean>("isNull", "(I)Z", index);
}

QString StringAt(const QJniObject& cursor, jint index) {
    return cursor.callObjectMethod("getString", "(I)Ljava/lang/String;", index).toString();
}

jlong LongAt(const QJniObject& cursor, jint index) { return cursor.callMethod<jlong>("getLong", "(I)J", index); }

QJniObject DocumentUriOf(const std::string& uri) {
    return AndroidDocumentUri(AndroidUri(QString::fromStdString(uri)));
}

jvalue Ref(const QJniObject& object) {
    jvalue value;
    value.l = object.object();
    return value;
}

struct Columns {
    explicit Columns(const QJniObject& cursor)
        : id(ColumnIndex(cursor, kColumns[kIdColumn])),
          name(ColumnIndex(cursor, kColumns[kNameColumn])),
          mime(ColumnIndex(cursor, kColumns[kMimeColumn])),
          size(ColumnIndex(cursor, kColumns[kSizeColumn])),
          modified(ColumnIndex(cursor, kColumns[kModifiedColumn])),
          flags(ColumnIndex(cursor, kColumns[kFlagsColumn])),
          writable(QJniObject::getStaticField<jint>(kDocument, "FLAG_SUPPORTS_WRITE")),
          directory_type(DirectoryMimeType().toString()) {}

    jint    id;
    jint    name;
    jint    mime;
    jint    size;
    jint    modified;
    jint    flags;
    jint    writable;
    QString directory_type;
};

void ReadInfo(const QJniObject& cursor, const Columns& c, cerfcore::HostDocumentInfo& info) {
    info = {};
    if (HasValue(cursor, c.name)) info.name = StringAt(cursor, c.name).toStdString();
    if (HasValue(cursor, c.mime)) info.directory = StringAt(cursor, c.mime) == c.directory_type;
    if (HasValue(cursor, c.size)) info.size = static_cast<uint64_t>(LongAt(cursor, c.size));
    if (HasValue(cursor, c.modified)) info.modified_ms = LongAt(cursor, c.modified);
    info.writable = !HasValue(cursor, c.flags) || (cursor.callMethod<jint>("getInt", "(I)I", c.flags) & c.writable) != 0;
}

bool Query(const QJniObject& target, QJniObject& cursor) {
    QJniEnvironment  env;
    const QJniObject resolver   = AndroidContentResolver();
    const jobjectArray projection = env->NewObjectArray(static_cast<jsize>(std::size(kColumns)),
                                                        env.findClass("java/lang/String"), nullptr);
    for (jsize i = 0; i < static_cast<jsize>(std::size(kColumns)); ++i)
        env->SetObjectArrayElement(projection, i, DocumentConstant(kColumns[i]).object<jstring>());
    const jmethodID query = env.findMethod(env.findClass(kContentResolverClass), "query",
                                           "(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;"
                                           "[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;");
    jobject rows = env->CallObjectMethod(resolver.object(), query, target.object(), projection, nullptr, nullptr, nullptr);
    env->DeleteLocalRef(projection);
    if (!JavaCallSucceeded(env, rows != nullptr)) return false;
    cursor = QJniObject::fromLocalRef(rows);
    return true;
}

bool ContractUri(const char* method, const char* signature, std::initializer_list<jvalue> args, std::string& uri) {
    QJniEnvironment           env;
    const jclass              contract = env.findClass(kDocumentsContractClass);
    const std::vector<jvalue> values(args);
    const jobject result = env->CallStaticObjectMethodA(contract, env.findStaticMethod(contract, method, signature),
                                                        values.data());
    if (!JavaCallSucceeded(env, result != nullptr)) return false;
    uri = QJniObject::fromLocalRef(result).toString().toStdString();
    return true;
}

}

namespace cerfcore {

namespace host {

int OpenHostDocument(const std::string& uri, const char* mode) {
    QJniEnvironment  env;
    const QJniObject resolver  = AndroidContentResolver();
    const QJniObject target    = DocumentUriOf(uri);
    const QJniObject mode_text = QJniObject::fromString(QString::fromLatin1(mode));
    const jmethodID  open      = env.findMethod(env.findClass(kContentResolverClass), "openFileDescriptor",
                                                "(Landroid/net/Uri;Ljava/lang/String;)Landroid/os/ParcelFileDescriptor;");
    jobject descriptor = env->CallObjectMethod(resolver.object(), open, target.object(), mode_text.object<jstring>());
    if (!JavaCallSucceeded(env, descriptor != nullptr)) return -1;
    return QJniObject::fromLocalRef(descriptor).callMethod<jint>("detachFd");
}

bool QueryHostDocument(const std::string& uri, HostDocumentInfo& info) {
    QJniObject cursor;
    if (!Query(DocumentUriOf(uri), cursor)) return false;
    const bool found = cursor.callMethod<jboolean>("moveToFirst");
    if (found) ReadInfo(cursor, Columns(cursor), info);
    else errno = ENOENT;
    cursor.callMethod<void>("close");
    return found;
}

bool ListHostDocumentChildren(const std::string& uri, std::vector<HostDocumentEntry>& children) {
    const QJniObject parent = DocumentUriOf(uri);
    const QJniObject id     = QJniObject::callStaticObjectMethod(kDocumentsContractClass, "getDocumentId",
                                                                 "(Landroid/net/Uri;)Ljava/lang/String;", parent.object());
    if (!id.isValid()) {
        errno = EINVAL;
        return false;
    }
    const QJniObject list = QJniObject::callStaticObjectMethod(
        kDocumentsContractClass, "buildChildDocumentsUriUsingTree",
        "(Landroid/net/Uri;Ljava/lang/String;)Landroid/net/Uri;", parent.object(), id.object<jstring>());
    QJniObject cursor;
    if (!Query(list, cursor)) return false;
    const Columns columns(cursor);
    while (cursor.callMethod<jboolean>("moveToNext")) {
        HostDocumentEntry entry;
        ReadInfo(cursor, columns, entry.info);
        const QJniObject child =
            AndroidTreeDocumentUri(parent, QJniObject::fromString(StringAt(cursor, columns.id)));
        entry.uri = child.toString().toStdString();
        children.push_back(std::move(entry));
    }
    cursor.callMethod<void>("close");
    return true;
}

bool CreateHostDocument(const std::string& parent_uri, bool directory, const std::string& name,
                        std::string& created_uri) {
    const QJniObject resolver = AndroidContentResolver();
    const QJniObject parent   = DocumentUriOf(parent_uri);
    const QJniObject mime =
        directory ? DirectoryMimeType() : QJniObject::fromString(QString::fromLatin1(kOctetStream));
    const QJniObject display = QJniObject::fromString(QString::fromStdString(name));
    return ContractUri("createDocument",
                       "(Landroid/content/ContentResolver;Landroid/net/Uri;Ljava/lang/String;Ljava/lang/String;)"
                       "Landroid/net/Uri;",
                       {Ref(resolver), Ref(parent), Ref(mime), Ref(display)}, created_uri);
}

bool DeleteHostDocument(const std::string& uri) {
    QJniEnvironment  env;
    const QJniObject resolver = AndroidContentResolver();
    const QJniObject target   = DocumentUriOf(uri);
    const jclass     contract = env.findClass(kDocumentsContractClass);
    const jmethodID  remove   = env.findStaticMethod(contract, "deleteDocument",
                                                     "(Landroid/content/ContentResolver;Landroid/net/Uri;)Z");
    const jboolean deleted = env->CallStaticBooleanMethod(contract, remove, resolver.object(), target.object());
    return JavaCallSucceeded(env, deleted != JNI_FALSE);
}

bool RenameHostDocument(const std::string& uri, const std::string& name, std::string& renamed_uri) {
    const QJniObject resolver = AndroidContentResolver();
    const QJniObject target   = DocumentUriOf(uri);
    const QJniObject display  = QJniObject::fromString(QString::fromStdString(name));
    return ContractUri("renameDocument",
                       "(Landroid/content/ContentResolver;Landroid/net/Uri;Ljava/lang/String;)Landroid/net/Uri;",
                       {Ref(resolver), Ref(target), Ref(display)}, renamed_uri);
}

bool MoveHostDocument(const std::string& uri, const std::string& parent_uri, const std::string& target_parent_uri,
                      std::string& moved_uri) {
    const QJniObject resolver = AndroidContentResolver();
    const QJniObject source   = DocumentUriOf(uri);
    const QJniObject parent   = DocumentUriOf(parent_uri);
    const QJniObject target   = DocumentUriOf(target_parent_uri);
    return ContractUri("moveDocument",
                       "(Landroid/content/ContentResolver;Landroid/net/Uri;Landroid/net/Uri;Landroid/net/Uri;)"
                       "Landroid/net/Uri;",
                       {Ref(resolver), Ref(source), Ref(parent), Ref(target)}, moved_uri);
}

}

}
