#include "cerfman/file_access.h"
#include "frontend_window.h"
#include "qt_emulator_window.h"
#include "qt_file_filters.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/service.h>
#include <cerfcore/host/machine_requests.h>

#include <QStringList>
#include <QUrl>
#include <QVariantList>
#include <QVariantMap>

#include <cstdint>
#include <string>
#include <vector>

namespace cerffrontend {

namespace {

class QtMachineRequests : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override {
        emu_.Get<cerfcore::MachineRequests>().Subscribe([this](const cerfcore::MachineRequest& request) {
            emu_.Get<FrontendWindow>().RunOnUiThread([this, request] { Answer(request); });
        });
    }

private:
    void Answer(const cerfcore::MachineRequest& request) {
        cerfcore::MachineReply reply;
        switch (request.kind) {
            case cerfcore::MachineRequestKind::kPath: {
                const std::vector<std::string> picked = Pick(request, false);
                reply.cancelled                       = picked.empty();
                if (!picked.empty()) reply.path = picked.front();
                break;
            }
            case cerfcore::MachineRequestKind::kDocuments:
                reply.documents = Pick(request, true);
                reply.cancelled = reply.documents.empty();
                break;
            case cerfcore::MachineRequestKind::kSize:
                reply.size      = AskSize(request);
                reply.cancelled = reply.size == 0;
                break;
        }
        emu_.Get<cerfcore::MachineRequests>().Reply(request.serial, reply);
    }

    std::vector<std::string> Pick(const cerfcore::MachineRequest& request, bool multiple) {
        QString     title = multiple ? QStringLiteral("Choose files") : QStringLiteral("Choose file");
        QStringList filters;
        if (request.id == "compact_flash_image") title = QStringLiteral("Choose CompactFlash image");
        if (request.id == "media_image") title = QStringLiteral("Choose existing media image");
        if (request.id == "compact_flash_documents")
            title = QStringLiteral("Choose files to write into the CompactFlash image");
        if (!request.extensions.empty()) {
            QStringList patterns;
            for (const std::string& ext : request.extensions) patterns << QStringLiteral("*.") + QString::fromStdString(ext);
            const QString kind = request.id == "media_image" ? QStringLiteral("Disk images") : QStringLiteral("CF image");
            filters << NameFilter(kind, patterns);
        }
        filters << AllFilesNameFilter();
        const QVariant result = emu_.Get<QtEmulatorWindow>().RunDialog(
            QStringLiteral("EmulatorFileDialog"),
            QVariantMap{{QStringLiteral("title"), title},
                        {QStringLiteral("nameFilters"), filters},
                        {QStringLiteral("multiple"), multiple}});
        std::vector<std::string> out;
        const FileAccess&        files = emu_.Get<FileAccess>();
        for (const QVariant& url : result.toList()) {
            const QString path = files.LocalPath(QUrl(url.toString()));
            if (!path.isEmpty()) out.push_back(path.toStdString());
        }
        return out;
    }

    uint64_t AskSize(const cerfcore::MachineRequest& request) {
        const QString caption =
            QStringLiteral("Card data size in MiB (minimum %1):").arg(static_cast<qulonglong>(request.minimum));
        const QVariantMap field{{QStringLiteral("label"), caption},
                                {QStringLiteral("value"), static_cast<qulonglong>(request.recommended)},
                                {QStringLiteral("unit"), QString()}};
        const QVariantList values =
            emu_.Get<QtEmulatorWindow>()
                .RunDialog(QStringLiteral("NumberPromptDialog"),
                           QVariantMap{{QStringLiteral("title"), QStringLiteral("Generate CompactFlash image")},
                                       {QStringLiteral("minimum"), static_cast<qulonglong>(request.minimum)},
                                       {QStringLiteral("maximum"), static_cast<qulonglong>(request.maximum)},
                                       {QStringLiteral("fields"), QVariantList{field}}})
                .toList();
        return values.isEmpty() ? 0u : values.front().toULongLong();
    }
};

}

REGISTER_SERVICE(QtMachineRequests);

}
