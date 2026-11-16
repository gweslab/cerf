#include "password_gate.h"

#include "manager_engine.h"

#include "../CerfStyle/touch_frontend.h"
#include "../enterprise_config.h"
#include "../process_sign_in.h"
#include "../qt_resource_paths.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QVariant>
#include <QVariantMap>

#include <utility>

REGISTER_SERVICE(PasswordGate);

namespace {

using cerffrontend::EnterpriseConfig;
using cerffrontend::ProcessSignIn;

constexpr char kWindowType[] = "PasswordGateWindow";

}

bool PasswordGate::Locked() const { return emu_.Get<EnterpriseConfig>().Enabled() && !ProcessSignIn::SignedIn(); }

QString PasswordGate::LogoSource() const {
    return SvgFileImageUrl(QString::fromStdString(emu_.Get<EnterpriseConfig>().LogoFile()));
}

void PasswordGate::GuardCerfman(std::function<void()> passed, std::function<void()> refused) {
    if (!Locked()) {
        passed();
        return;
    }
    passed_  = std::move(passed);
    refused_ = std::move(refused);
    Open(true);
}

void PasswordGate::Open(bool dismissable) {
    QVariantMap properties{{QStringLiteral("dismissable"), dismissable}};
    if (TouchFrontend::Active()) {
        properties.insert(QStringLiteral("mobile"), true);
        properties.insert(QStringLiteral("visibility"), QVariant::fromValue(QWindow::Maximized));
    } else {
        properties.insert(QStringLiteral("visible"), true);
    }
    window_ = qobject_cast<QWindow*>(emu_.Get<ManagerEngine>().Open(QString::fromLatin1(kWindowType), properties));
}

bool PasswordGate::Submit(const QString& password) {
    if (password.toStdString() != emu_.Get<EnterpriseConfig>().Password()) return false;
    ProcessSignIn::SignIn();
    refused_ = {};
    if (std::function<void()> passed = std::exchange(passed_, {})) passed();
    return true;
}

void PasswordGate::Closed() {
    window_.clear();
    passed_ = {};
    if (std::function<void()> refused = std::exchange(refused_, {})) refused();
}

void PasswordGate::Relock(QWindow* cerfman) {
    if (!Locked() || window_) return;
    passed_ = [cerfman] { cerfman->show(); };
    Open(false);
    cerfman->hide();
}
