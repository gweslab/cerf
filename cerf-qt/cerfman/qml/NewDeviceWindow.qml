import QtQuick
import CerfStyle

PageWindow {
    id: dialog
    required property QtObject flows

    title: qsTr("New")
    width: 820
    height: 600
    minimumWidth: Theme.windowMinimumWidth
    minimumHeight: Theme.windowMinimumHeight

    NewDeviceWizard {
        anchors.fill: parent
        flows: dialog.flows
        onFinished: dialog.close()
    }
}
