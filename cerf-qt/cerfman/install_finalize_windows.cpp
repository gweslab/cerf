#include "install_finalize.h"

#include "host_error_text.h"
#include "install_directories.h"

#include "../../uninstaller-win32/shell_integration_windows.h"

#include "../install_root_files.h"
#include "../product_links.h"
#include "../version.h"

#define NOMINMAX
#include <windows.h>

#include <QDir>
#include <QDirIterator>
#include <QFileInfo>

#include <functional>
#include <string>

namespace {

std::wstring Wide(const QString& text) { return QDir::toNativeSeparators(text).toStdWString(); }

bool Report(bool ok, const std::wstring& failure, QString& error) {
    if (!ok) error = QString::fromStdWString(failure);
    return ok;
}

bool CreateDesktopShortcut(const QString& frontend_path, QString& error) {
    std::wstring path;
    std::wstring failure;
    const bool   ok = shell_integration::DesktopShortcutPath(path, failure) &&
                    shell_integration::WriteShortcut(path, Wide(frontend_path), shell_integration::ProductName(),
                                                     failure);
    return Report(ok, failure, error);
}

bool CreateStartMenuEntries(const QString& frontend_path, const QString& uninstaller_path, QString& error) {
    std::wstring folder;
    std::wstring failure;
    const std::wstring product   = shell_integration::ProductName();
    const std::wstring uninstall = shell_integration::UninstallName();
    const bool         ok =
        shell_integration::StartMenuFolder(folder, failure) &&
        shell_integration::WriteShortcut(shell_integration::ShortcutPath(folder, product), Wide(frontend_path),
                                         product, failure) &&
        shell_integration::WriteShortcut(shell_integration::ShortcutPath(folder, uninstall), Wide(uninstaller_path),
                                         uninstall, failure);
    return Report(ok, failure, error);
}

qint64 DirectoryKilobytes(const QString& install_dir) {
    const std::wstring staging = Wide(StagingDirectory(install_dir));
    qint64             total   = 0;
    QDirIterator       it(install_dir, QDir::Files | QDir::Hidden | QDir::System, QDirIterator::Subdirectories);
    while (it.hasNext()) {
        const QFileInfo info = it.nextFileInfo();
        if (!shell_integration::InsideDirectory(Wide(info.absoluteFilePath()), staging)) total += info.size();
    }
    return total / 1024;
}

bool SetString(HKEY key, const wchar_t* name, const QString& value, LONG& status) {
    const std::wstring text = value.toStdWString();
    status = RegSetValueExW(key, name, 0, REG_SZ, reinterpret_cast<const BYTE*>(text.c_str()),
                            DWORD((text.size() + 1) * sizeof(wchar_t)));
    return status == ERROR_SUCCESS;
}

bool SetDword(HKEY key, const wchar_t* name, DWORD value, LONG& status) {
    status = RegSetValueExW(key, name, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value));
    return status == ERROR_SUCCESS;
}

bool RegisterUninstallEntry(const QString& install_dir, const QString& frontend_path,
                            const QString& uninstaller_path, QString& error) {
    HKEY       key    = nullptr;
    const LONG opened = RegCreateKeyExW(HKEY_CURRENT_USER, shell_integration::kUninstallKey, 0, nullptr, 0,
                                        KEY_SET_VALUE, nullptr, &key, nullptr);
    if (opened != ERROR_SUCCESS) {
        error = QStringLiteral("cannot create the uninstall registry key (%1)").arg(HostErrorText(uint32_t(opened)));
        return false;
    }
    const QString version = QStringLiteral("%1.%2.%3.%4")
                                .arg(CERF_VERSION_MAJOR)
                                .arg(CERF_VERSION_MINOR)
                                .arg(CERF_VERSION_PATCH)
                                .arg(CERF_VERSION_BUILD);
    LONG       status = ERROR_SUCCESS;
    const bool written =
        SetString(key, L"DisplayName", QString::fromStdWString(shell_integration::ProductName()), status) &&
        SetString(key, L"DisplayIcon", QDir::toNativeSeparators(frontend_path) + QStringLiteral(",0"), status) &&
        SetString(key, L"DisplayVersion", version, status) &&
        SetString(key, L"Publisher", QString::fromUtf8(cerffrontend::kProductAuthor), status) &&
        SetString(key, shell_integration::kInstallLocationValue, QDir::toNativeSeparators(install_dir), status) &&
        SetString(key, L"UninstallString",
                  QStringLiteral("\"%1\"").arg(QDir::toNativeSeparators(uninstaller_path)), status) &&
        SetString(key, L"HelpLink", QString::fromUtf8(cerffrontend::kWebsiteUrl), status) &&
        SetDword(key, L"NoModify", 1, status) && SetDword(key, L"NoRepair", 1, status) &&
        SetDword(key, L"EstimatedSize", DWORD(DirectoryKilobytes(install_dir)), status);
    RegCloseKey(key);
    if (!written)
        error = QStringLiteral("cannot write the uninstall registry values (%1)").arg(HostErrorText(uint32_t(status)));
    return written;
}

void Create(const InstallRetryGate& gate, const QString& what, const std::function<bool(QString&)>& action) {
    const QString step = QStringLiteral("Creating %1").arg(what);
    gate.Report(step);
    QString failure;
    if (!gate.Attempt(QStringLiteral("Create failed"), step, action, failure))
        gate.Report(QStringLiteral("  %1 not created (%2)").arg(what, failure));
}

}

void FinalizeInstall(const QString& install_dir, const QString& frontend_path, const InstallOptions& options,
                     const InstallRetryGate& gate) {
    const QString      uninstaller = QDir(install_dir).filePath(QString::fromLatin1(cerffrontend::kUninstallerFileName));
    const std::wstring dir         = Wide(install_dir);
    if (options.desktop_icon || (!options.fresh && shell_integration::OwnsDesktopShortcut(dir)))
        Create(gate, QStringLiteral("the desktop shortcut"),
               [&](QString& failure) { return CreateDesktopShortcut(frontend_path, failure); });
    if (options.start_menu || (!options.fresh && shell_integration::OwnsStartMenuEntries(dir)))
        Create(gate, QStringLiteral("the Start menu entries"),
               [&](QString& failure) { return CreateStartMenuEntries(frontend_path, uninstaller, failure); });
    if (options.fresh || shell_integration::OwnsUninstallEntry(dir))
        Create(gate, QStringLiteral("the Programs and Features entry"),
               [&](QString& failure) { return RegisterUninstallEntry(install_dir, frontend_path, uninstaller, failure); });
}
