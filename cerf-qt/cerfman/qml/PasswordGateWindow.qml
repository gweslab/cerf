import QtQuick
import QtQuick.Layouts
import CerfStyle

PageWindow {
    id: host
    property bool mobile: false
    property bool dismissable: true
    property bool passed: false

    function goBack() {
        if (dismissable)
            host.close()
        return true
    }

    title: form.title
    width: 420
    height: 320
    minimumWidth: mobile ? 0 : Theme.windowMinimumWidth
    minimumHeight: mobile ? 0 : Theme.windowMinimumHeight

    onClosing: close => {
        if (!passed && !dismissable) {
            close.accepted = false
            return
        }
        PasswordGate.Closed()
    }

    Component.onCompleted: form.takeFocus()

    Shortcut {
        sequence: "Escape"
        enabled: host.dismissable
        onActivated: host.close()
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.spaceXXXL

        Item {
            Layout.fillHeight: true
        }
        PasswordGateForm {
            id: form
            Layout.alignment: Qt.AlignHCenter
            Layout.fillWidth: true
            onPassed: {
                host.passed = true
                host.close()
            }
        }
        Item {
            Layout.fillHeight: true
        }
    }
}
