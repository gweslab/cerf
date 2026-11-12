#include "host_input_method.h"

#include <QtCore/qcoreapplication_platform.h>

namespace {

constexpr int kSdkImeInsets = 30;

}

bool InputMethodReportsClose() { return QNativeInterface::QAndroidApplication::sdkVersion() >= kSdkImeInsets; }

Qt::InputMethodHints InputMethodHints() {
    return Qt::ImhNoPredictiveText | Qt::ImhNoAutoUppercase | Qt::ImhMultiLine | Qt::ImhNoFullscreen;
}
