#include "soft_keyboard_request.h"

#include <QCoreApplication>
#include <QGuiApplication>
#include <QInputMethod>
#include <QQuickItem>

namespace {

constexpr int kSdkImeInsets = 30;

}

SoftKeyboardRequest::SoftKeyboardRequest(QQuickItem& input_item) : input_item_(input_item) {
    connect(QGuiApplication::inputMethod(), &QInputMethod::visibleChanged, this,
            &SoftKeyboardRequest::OnKeyboardVisibleChanged);
    connect(&input_item_, &QQuickItem::activeFocusChanged, this, [this](bool focused) {
        if (!focused) Set(false);
    });
}

void SoftKeyboardRequest::Toggle() {
    QInputMethod* input = QGuiApplication::inputMethod();
    if (requested_) {
        Set(false);
        input->hide();
        return;
    }
    input_item_.forceActiveFocus(Qt::OtherFocusReason);
    Set(true);
    input->show();
}

void SoftKeyboardRequest::SetOffered(bool offered) {
    if (offered == offered_) return;
    offered_ = offered;
    if (!offered && requested_) Toggle();
    emit offeredChanged();
}

void SoftKeyboardRequest::OnKeyboardVisibleChanged() {
    if (QGuiApplication::inputMethod()->isVisible()) {
        if (input_item_.hasActiveFocus()) Set(true);
        return;
    }
    if (QNativeInterface::QAndroidApplication::sdkVersion() >= kSdkImeInsets) Set(false);
}

void SoftKeyboardRequest::Set(bool requested) {
    if (requested == requested_) return;
    requested_ = requested;
    emit requestedChanged();
}
