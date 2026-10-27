#include "../calibration_warning_prompt.h"

#include "mobile_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/log.h>
#include <cerfcore/host/customizations_editor.h>

#include <QMetaObject>
#include <QPointer>
#include <QString>
#include <QStringList>
#include <QVariantMap>

namespace {

constexpr const char* kParagraphs[] = {
    "You are running a custom Guest Additions driver, however the calibration screen NEEDS the stock input. "
    "The stock input might freak out on a custom resolution.",
    "You need to temporarily switch to the stock input and change your resolution if it doesn't match the "
    "stock device one. CERF will switch you back after you complete the calibration.",
};

constexpr char kSwitchChoice[]     = "switch";
constexpr char kResolutionChoice[] = "resolution";

class MobileCalibrationWarningPrompt : public cerffrontend::CalibrationWarningPrompt {
public:
    using cerffrontend::CalibrationWarningPrompt::CalibrationWarningPrompt;

    bool ShouldRegister() override { return emu_.Get<cerfcore::DeviceConfig>().guest_additions; }

    cerffrontend::CalibWarningChoice Show() override {
        if (showing_) return cerffrontend::CalibWarningChoice::kDismissed;
        showing_    = true;
        dismissed_  = false;
        auto choice = cerffrontend::CalibWarningChoice::kDismissed;
        while (!dismissed_) {
            const QString picked =
                emu_.Get<MobileEmulatorWindow>()
                    .RunDialog(QStringLiteral("EmulatorCalibrationDialog"),
                               QVariantMap{{QStringLiteral("texts"), Texts()}}, [this](QObject* d) { dialog_ = d; })
                    .toString();
            dialog_ = nullptr;
            LOG(GuestAdditions, "[CALIB] warning answer '%s'%s\n", qUtf8Printable(picked),
                dismissed_ ? " after dismiss" : "");
            if (picked == QLatin1String(kSwitchChoice)) {
                choice = cerffrontend::CalibWarningChoice::kSwitchToStock;
                break;
            }
            if (picked != QLatin1String(kResolutionChoice) || dismissed_) break;
            if (emu_.Get<cerfcore::CustomizationsEditor>().Open(true)) break;
        }
        showing_ = false;
        return choice;
    }

    void Dismiss() override {
        dismissed_ = true;
        if (dialog_) QMetaObject::invokeMethod(dialog_.data(), "close");
    }

private:
    static QVariantMap Texts() {
        QStringList paragraphs;
        for (const char* p : kParagraphs) paragraphs.append(QString::fromUtf8(p));
        return {{QStringLiteral("title"), QString::fromUtf8(kTitle)},
                {QStringLiteral("paragraphs"), paragraphs},
                {QStringLiteral("switchLabel"), QString::fromUtf8(kSwitchLabel)},
                {QStringLiteral("changeLabel"), QString::fromUtf8(kChangeLabel)},
                {QStringLiteral("closeLabel"), QString::fromUtf8(kCloseLabel)},
                {QStringLiteral("switchChoice"), QString::fromLatin1(kSwitchChoice)},
                {QStringLiteral("resolutionChoice"), QString::fromLatin1(kResolutionChoice)}};
    }

    QPointer<QObject> dialog_;
    bool              showing_   = false;
    bool              dismissed_ = false;
};

}

REGISTER_SERVICE_AS(MobileCalibrationWarningPrompt, cerffrontend::CalibrationWarningPrompt);
