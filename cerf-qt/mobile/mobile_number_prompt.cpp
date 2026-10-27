#include <cerfcore/host/number_prompt.h>

#include "mobile_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QVariantList>
#include <QVariantMap>

#include <cstdint>
#include <limits>

namespace {

class MobileNumberPrompt : public cerfcore::NumberPrompt {
public:
    using cerfcore::NumberPrompt::NumberPrompt;

    uint32_t AskAtLeast(const std::string& title, const std::string& caption, uint32_t minimum) override {
        const QVariantMap field{{QStringLiteral("label"), QString::fromStdString(caption)},
                                {QStringLiteral("value"), static_cast<qulonglong>(minimum)},
                                {QStringLiteral("unit"), QString()}};
        const QVariantList values =
            emu_.Get<MobileEmulatorWindow>()
                .RunDialog(QStringLiteral("NumberPromptDialog"),
                           QVariantMap{{QStringLiteral("title"), QString::fromStdString(title)},
                                       {QStringLiteral("minimum"), static_cast<qulonglong>(minimum)},
                                       {QStringLiteral("maximum"),
                                        static_cast<qulonglong>(std::numeric_limits<uint32_t>::max())},
                                       {QStringLiteral("fields"), QVariantList{field}}})
                .toList();
        return values.isEmpty() ? 0u : values.front().toUInt();
    }
};

}

REGISTER_SERVICE_AS(MobileNumberPrompt, cerfcore::NumberPrompt);
