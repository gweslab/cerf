import QtQuick
import CerfStyle

PageWindow {
    id: dialog
    required property QtObject flows
    required property string start

    title: start === "download" ? qsTr("Download ROMs") : qsTr("New device")
    width: 820
    height: 600
    minimumWidth: Theme.windowMinimumWidth
    minimumHeight: Theme.windowMinimumHeight

    NewDeviceWizard {
        anchors.fill: parent
        flows: dialog.flows
        start: dialog.start
        onClosed: dialog.close()
    }
}
