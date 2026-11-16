import QtQuick
import CerfStyle

EmulatorDialog {
    id: dialog

    title: Theme.touchPlatform ? "" : form.title
    preferredWidth: 320
    contentHeight: form.implicitHeight

    onOpened: form.takeFocus()

    PasswordGateForm {
        id: form
        width: dialog.availableWidth
        onPassed: dialog.close()
    }
}
