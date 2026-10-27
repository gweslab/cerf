#include "install_copier.h"

#include "filesystem_path.h"
#include "global_config_migration.h"

#include "../install_root_files.h"

#include <QDir>

#include <algorithm>
#include <system_error>

namespace fs = std::filesystem;

namespace {

constexpr char        kBundleSuffix[]   = ".app";
constexpr const char* kGlobalConfigName = cerffrontend::kGlobalConfigFileName;

bool IsBundle(const fs::directory_entry& entry) {
    std::error_code ec;
    return entry.path().extension() == kBundleSuffix && entry.is_directory(ec) && !entry.is_symlink(ec);
}

bool Fail(const fs::path& path, const std::error_code& ec, QString& error) {
    error = QStringLiteral("%1: %2").arg(QDir::toNativeSeparators(PathText(path)), ErrorCodeText(ec));
    return false;
}

bool CopyEntry(const fs::path& source, const fs::path& destination, QString& error) {
    std::error_code ec;
    if (!fs::is_symlink(fs::symlink_status(source, ec))) return CopyFileTo(source, destination, error);
    if (!MakeDirectory(PathText(destination.parent_path()), error) || !RemoveEntry(destination, error)) return false;
    const fs::path target = fs::read_symlink(source, ec);
    if (ec) return Fail(source, ec, error);
    fs::create_symlink(target, destination, ec);
    return ec ? Fail(destination, ec, error) : true;
}

bool ReplaceBundle(const fs::path& source, const fs::path& destination, QString& error) {
    if (!RemoveEntry(destination, error)) return false;
    std::error_code ec;
    fs::copy(source, destination, fs::copy_options::recursive | fs::copy_options::copy_symlinks, ec);
    return ec ? Fail(destination, ec, error) : true;
}

}

bool InstallCopier::Step(const QString& title, const QString& what, const InstallRetryGate::Action& action,
                         QString& error) const {
    QString failure;
    if (gate_.Attempt(title, what, action, failure)) return true;
    error = QStringLiteral("%1: cancelled").arg(what);
    return false;
}

bool InstallCopier::ListBundles(QString& error) {
    std::error_code ec;
    for (auto it = fs::directory_iterator(from_, ec); !ec && it != fs::directory_iterator(); it.increment(ec))
        if (IsBundle(*it)) bundles_.push_back(it->path().filename());
    if (ec) return Fail(from_, ec, error);
    std::sort(bundles_.begin(), bundles_.end());
    return true;
}

bool InstallCopier::ListPayload(QString& error) {
    std::error_code ec;
    for (auto it = fs::recursive_directory_iterator(from_, ec); !ec && it != fs::recursive_directory_iterator();
         it.increment(ec)) {
        const fs::directory_entry& entry = *it;
        if (it.depth() == 0 && IsBundle(entry)) {
            it.disable_recursion_pending();
            continue;
        }
        std::error_code status_ec;
        if (entry.is_symlink(status_ec) || !entry.is_directory(status_ec)) {
            const fs::path relative = entry.path().lexically_relative(from_);
            if (relative != fs::path(kGlobalConfigName)) payload_.push_back(relative);
        }
    }
    if (ec) return Fail(from_, ec, error);
    std::sort(payload_.begin(), payload_.end());
    return true;
}

void InstallCopier::ListRetiredEntries() {
    for (const char* name : kRetiredEntries)
        if (!EntryExists(from_ / name) && EntryExists(to_ / name)) retired_.push_back(name);
}

bool InstallCopier::Prepare(const QString& upgrade_dir, const QString& install_dir, QString& error) {
    from_ = PathOf(upgrade_dir);
    to_   = PathOf(install_dir);
    const std::optional<Json> staged = ReadJsonObject(PathText(from_ / kGlobalConfigName), error);
    if (!staged) return false;
    staged_config_ = *staged;
    if (!ListBundles(error) || !ListPayload(error)) return false;
    ListRetiredEntries();
    return true;
}

bool InstallCopier::CopyAll(const std::vector<fs::path>& relatives, CopyAction copy, QString& error) {
    for (const fs::path& relative : relatives) {
        const QString name = PathText(relative);
        gate_.Report(QStringLiteral("  %1").arg(name));
        if (!Step(QStringLiteral("Copy failed"), QStringLiteral("Copying %1").arg(name),
                  [&](QString& failure) { return copy(from_ / relative, to_ / relative, failure); }, error))
            return false;
    }
    return true;
}

bool InstallCopier::RemoveRetiredEntries(QString& error) {
    for (const char* name : retired_) {
        const QString what = QStringLiteral("Removing %1").arg(QString::fromLatin1(name));
        gate_.Report(what);
        if (!Step(QStringLiteral("Remove failed"), what,
                  [&](QString& failure) { return RemoveEntry(to_ / name, failure); }, error))
            return false;
    }
    return true;
}

bool InstallCopier::Apply(QString& error) {
    gate_.Report(QStringLiteral("Installing into %1").arg(PathText(to_)));
    if (!CopyAll(bundles_, ReplaceBundle, error) || !CopyAll(payload_, CopyEntry, error) ||
        !RemoveRetiredEntries(error))
        return false;
    const QString what = QStringLiteral("Migrating %1").arg(QString::fromLatin1(kGlobalConfigName));
    gate_.Report(what);
    if (!Step(QStringLiteral("Migration failed"), what,
              [&](QString& failure) {
                  return MigrateGlobalConfig(staged_config_, PathText(to_ / kGlobalConfigName), failure);
              },
              error))
        return false;
    gate_.Report(QStringLiteral("Installation complete"));
    return true;
}
