#include "calibration_warning_prompt.h"

#include "qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/log.h>

#include <QMetaObject>
#include <QPointer>
#include <QString>
#include <QStringList>
#include <QVariantMap>

namespace {

constexpr const char* kParagraphs[] = {
    "The calibration can only be passed with a stock input device. The emulator will switch you back to the enhanced input mode once you complete the calibration.",
    "If you are running on a custom resolution - switch it to a stock one - built-in input device might not accept custom resolution."
};

constexpr char kSwitchChoice[]     = "switch";
constexpr char kResolutionChoice[] = "resolution";

class QtCalibrationWarningPrompt : public cerffrontend::CalibrationWarningPrompt {
public:
    using cerffrontend::CalibrationWarningPrompt::CalibrationWarningPrompt;

    bool ShouldRegister() override { return emu_.Get<cerfcore::DeviceConfig>().guest_additions; }

    cerffrontend::CalibWarningChoice Show() override {
        if (showing_) return cerffrontend::CalibWarningChoice::kDismissed;
        showing_   = true;
        dismissed_ = false;
        const QString picked =
            emu_.Get<QtEmulatorWindow>()
                .RunDialog(QStringLiteral("EmulatorCalibrationDialog"), QVariantMap{{QStringLiteral("texts"), Texts()}},
                           [this](QObject* d) { dialog_ = d; })
                .toString();
        dialog_  = nullptr;
        showing_ = false;
        LOG(GuestAdditions, "[CALIB] warning answer '%s'%s\n", qUtf8Printable(picked),
            dismissed_ ? " after dismiss" : "");
        if (picked == QLatin1String(kSwitchChoice)) return cerffrontend::CalibWarningChoice::kSwitchToStock;
        if (picked == QLatin1String(kResolutionChoice) && !dismissed_)
            return cerffrontend::CalibWarningChoice::kChangeResolution;
        return cerffrontend::CalibWarningChoice::kDismissed;
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

REGISTER_SERVICE_AS(QtCalibrationWarningPrompt, cerffrontend::CalibrationWarningPrompt);
