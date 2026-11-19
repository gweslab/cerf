#include "qt_shutdown_dialog.h"

#include "host_power_actions.h"
#include "html_link.h"
#include "qt_emulator_window.h"
#include "yes_no_prompt.h"

#include <cerfcore/boot/guest_cold_boot.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/guest_deep_sleep.h>
#include <cerfcore/socs/guest_cpu_reset.h>
#include <cerfcore/state/hibernation.h>

#include <QMetaObject>
#include <QString>
#include <QVariantList>

#include <functional>

REGISTER_SERVICE(QtShutdownDialog);

namespace {

using cerffrontend::HostPowerActions;
using cerffrontend::ShutdownAction;
using cerffrontend::ShutdownChoice;
using cerffrontend::ShutdownPrompt;
using cerffrontend::ShutdownTrigger;

constexpr int kNoAction = -1;

}

void QtShutdownDialog::OnReady() {
    window_ = &emu_.Get<QtEmulatorWindow>();
    emu_.Get<cerfcore::GuestDeepSleep>().RegisterSuspendListener([this](bool suspended) {
        window_->RunOnUiThread([this, suspended] {
            if (suspended) StopCountdown();
            FollowSleep();
        });
    });
}

void QtShutdownDialog::StopCountdown() {
    if (open_ && open_trigger_ == ShutdownTrigger::WindowClose && dialog_)
        QMetaObject::invokeMethod(dialog_.data(), "stopCountdown");
}

void QtShutdownDialog::FollowSleep() {
    if (emu_.Get<cerfcore::GuestDeepSleep>().Suspended()) {
        Show(ShutdownTrigger::GuestSleep);
        return;
    }
    if (!open_ || open_trigger_ != ShutdownTrigger::GuestSleep) return;
    withdrawn_ = true;
    window_->CloseDialogs();
}

void QtShutdownDialog::Show(ShutdownTrigger trigger) {
    auto& prompt = emu_.Get<ShutdownPrompt>();
    if (open_ || !prompt.Unattended()) {
        ShowDialog(trigger);
        return;
    }
    const ShutdownChoice choice = prompt.CommitUnattended();
    if (trigger == ShutdownTrigger::WindowClose) prompt.FinishCloseRequest(choice);
    Perform(trigger, choice);
}

void QtShutdownDialog::ShowDialog(ShutdownTrigger trigger) {
    auto& prompt = emu_.Get<ShutdownPrompt>();
    if (open_) {
        if (trigger == ShutdownTrigger::WindowClose) prompt.CancelCloseRequest();
        return;
    }
    open_                 = true;
    open_trigger_         = trigger;
    withdrawn_            = false;
    const QVariant result = window_->RunDialog(QStringLiteral("EmulatorShutdownDialog"),
                                               QVariantMap{{QStringLiteral("texts"), Texts(trigger)}},
                                               [this](QObject* dialog) { dialog_ = dialog; });
    dialog_.clear();
    if (withdrawn_) {
        open_ = false;
        return;
    }
    const ShutdownChoice choice = Choice(result);
    OfferAc(trigger, choice);
    open_ = false;
    if (trigger == ShutdownTrigger::WindowClose) prompt.FinishCloseRequest(choice);
    Perform(trigger, choice);
}

QVariantMap QtShutdownDialog::Texts(ShutdownTrigger trigger) {
    auto&        prompt = emu_.Get<ShutdownPrompt>();
    QVariantList actions;
    QVariantList descriptions;
    int          exit_action = kNoAction;
    shown_actions_           = prompt.Actions();
    for (ShutdownAction action : shown_actions_) {
        if (action == ShutdownAction::Exit) exit_action = static_cast<int>(actions.size());
        actions.append(QString::fromUtf8(prompt.ActionLabel(action)));
        descriptions.append(QString::fromUtf8(prompt.ActionDescription(action)));
    }
    return QVariantMap{
        {QStringLiteral("title"), QString::fromUtf8(prompt.Title())},
        {QStringLiteral("heading"), QString::fromUtf8(prompt.Heading())},
        {QStringLiteral("countsDown"), prompt.CountsDown(trigger)},
        {QStringLiteral("countdownMs"), static_cast<int>(ShutdownPrompt::kCountdownMs)},
        {QStringLiteral("intro"), QString::fromUtf8(prompt.Intro(trigger))},
        {QStringLiteral("actions"), actions},
        {QStringLiteral("exitAction"), exit_action},
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
}

ShutdownChoice QtShutdownDialog::Choice(const QVariant& result) {
    if (result.typeId() != QMetaType::QVariantMap) return ShutdownChoice::Cancel;
    const QVariantMap chosen = result.toMap();
    return emu_.Get<ShutdownPrompt>().Commit(
        shown_actions_[static_cast<size_t>(chosen.value(QStringLiteral("action")).toInt())],
        chosen.value(QStringLiteral("save")).toBool(), chosen.value(QStringLiteral("remember")).toBool());
}

void QtShutdownDialog::OfferAc(ShutdownTrigger trigger, ShutdownChoice choice) {
    auto&                       prompt     = emu_.Get<ShutdownPrompt>();
    const std::function<void()> plug_in_ac = prompt.AcOffer(trigger, choice);
    if (!plug_in_ac) return;
    if (emu_.Get<cerffrontend::YesNoPrompt>().Ask(prompt.PlugInAcQuestion(), prompt.PlugInAcReason(),
                                                  cerffrontend::YesNoLevel::kPlain,
                                                  cerffrontend::YesNoEnter::kYes) == cerffrontend::PromptAnswer::kYes)
        plug_in_ac();
}

void QtShutdownDialog::Perform(ShutdownTrigger trigger, ShutdownChoice choice) {
    auto& sleep = emu_.Get<cerfcore::GuestDeepSleep>();
    switch (choice) {
        case ShutdownChoice::Cancel:
            if (trigger == ShutdownTrigger::GuestSleep) sleep.Resume();
            else if (sleep.Suspended()) Show(ShutdownTrigger::GuestSleep);
            return;
        case ShutdownChoice::SoftReset: emu_.Get<cerfcore::GuestCpuReset>().WarmResetFromHost(); return;
        case ShutdownChoice::HardReset: emu_.Get<cerfcore::GuestColdBoot>().RequestHardResetFromHost(); return;
        case ShutdownChoice::Exit:      window_->BeginShutdownTeardown(); return;
        case ShutdownChoice::ExitSave:  SaveAndExit(false); return;
        case ShutdownChoice::SaveSuspendHost:
            emu_.Get<HostPowerActions>().RequireSuspend();
            SaveAndExit(true);
            return;
        case ShutdownChoice::SavePoweroffHost: emu_.Get<HostPowerActions>().PowerOff();
        case ShutdownChoice::SaveRestartHost:  emu_.Get<HostPowerActions>().Restart();
    }
}

void QtShutdownDialog::SaveAndExit(bool suspend_host) {
    if (saving_) return;
    saving_ = true;
    emu_.Get<cerfcore::Hibernation>().SaveAsync("", [this, suspend_host](bool saved) {
        window_->RunOnUiThread([this, saved, suspend_host] {
            saving_ = false;
            if (saved) {
                if (suspend_host) emu_.Get<HostPowerActions>().Suspend([this] { window_->BeginShutdownTeardown(); });
                else              window_->BeginShutdownTeardown();
                return;
            }
            emu_.Get<ShutdownPrompt>().CancelCloseRequest();
            if (emu_.Get<cerfcore::GuestDeepSleep>().Suspended()) ShowDialog(ShutdownTrigger::GuestSleep);
        });
    });
}
