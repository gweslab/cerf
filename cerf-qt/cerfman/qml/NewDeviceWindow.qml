import QtQuick
import CerfStyle

PageWindow {
    id: dialog
    required property QtObject flows
    readonly property int startWidth: 560
    readonly property int startHeight: 360
    readonly property int stepWidth: 820
    readonly property int stepHeight: 600

    function fitStep() {
        width = wizard.atStart ? startWidth : stepWidth
        height = wizard.atStart ? startHeight : stepHeight
        center()
    }

    title: qsTr("New")
    minimumWidth: Theme.windowMinimumWidth
    minimumHeight: Theme.windowMinimumHeight

    NewDeviceWizard {
        id: wizard
        anchors.fill: parent
        flows: dialog.flows
        onFinished: dialog.close()
        onAtStartChanged: dialog.fitStep()
    }

    Component.onCompleted: fitStep()
}
