#include <cerfcore/host/shutdown_host.h>

#include "mobile_emulator_window.h"

#include "../html_link.h"
#include "../shutdown_prompt.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QString>
#include <QVariantList>
#include <QVariantMap>

namespace {

using cerffrontend::ShutdownPrompt;
using cerffrontend::ShutdownPromptAction;

class MobileShutdownHost : public cerfcore::ShutdownHost {
public:
    using cerfcore::ShutdownHost::ShutdownHost;

    void RunPromptJob(std::function<void()> job) override {
        emu_.Get<MobileEmulatorWindow>().RunOnUiThread(std::move(job));
    }

    cerfcore::ShutdownChoice Ask(cerfcore::ShutdownTrigger trigger) override {
        if (open_) return cerfcore::ShutdownChoice::Cancel;
        auto&        prompt = emu_.Get<ShutdownPrompt>();
        QVariantList actions;
        QVariantList descriptions;
        for (int i = 0; i < ShutdownPrompt::kActionCount; ++i) {
            const auto action = static_cast<ShutdownPromptAction>(i);
            actions.append(QString::fromUtf8(prompt.ActionLabel(action)));
            descriptions.append(action == ShutdownPromptAction::Exit
                                    ? QString()
                                    : QString::fromUtf8(prompt.ResetDescription(action)));
        }
        const QVariantMap texts{
            {QStringLiteral("title"), QStringLiteral("Shut down")},
            {QStringLiteral("intro"), QString::fromUtf8(prompt.Intro(trigger))},
            {QStringLiteral("question"), QString::fromUtf8(prompt.Question())},
            {QStringLiteral("actions"), actions},
            {QStringLiteral("exitAction"), static_cast<int>(ShutdownPromptAction::Exit)},
            {QStringLiteral("descriptions"), descriptions},
            {QStringLiteral("okLabel"), QStringLiteral("OK")},
            {QStringLiteral("cancelLabel"), QString::fromUtf8(prompt.CancelLabel(trigger))},
            {QStringLiteral("saveTitle"), QString::fromUtf8(prompt.SaveTitle())},
            {QStringLiteral("saveDescription"),
             QStringLiteral("%1, %2").arg(QString::fromStdString(prompt.SaveDetail()),
                                          HtmlLink(QString::fromUtf8(prompt.SaveLinkUrl()),
                                                   QString::fromUtf8(prompt.SaveLinkText())))},
            {QStringLiteral("saveDefault"), prompt.SaveByDefault()},
            {QStringLiteral("rememberLabel"), QString::fromUtf8(prompt.RememberLabel())}};
        open_                 = true;
        const QVariant result = emu_.Get<MobileEmulatorWindow>().RunDialog(
            QStringLiteral("EmulatorShutdownDialog"), QVariantMap{{QStringLiteral("texts"), texts}});
        open_ = false;
        if (result.typeId() != QMetaType::QVariantMap) return cerfcore::ShutdownChoice::Cancel;
        const QVariantMap chosen = result.toMap();
        return prompt.Commit(static_cast<ShutdownPromptAction>(chosen.value(QStringLiteral("action")).toInt()),
                             chosen.value(QStringLiteral("save")).toBool(),
                             chosen.value(QStringLiteral("remember")).toBool());
    }

    void DismissAsCancel() override { emu_.Get<MobileEmulatorWindow>().CloseDialogs(); }

    void BeginTeardown() override { emu_.Get<MobileEmulatorWindow>().BeginShutdownTeardown(); }

    void CancelTeardown() override { emu_.Get<ShutdownPrompt>().CancelCloseRequest(); }

private:
    bool open_ = false;
};

}

REGISTER_SERVICE_AS(MobileShutdownHost, cerfcore::ShutdownHost);
