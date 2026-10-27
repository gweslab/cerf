import QtQuick
import QtQuick.Controls
import CerfStyle

NumberPromptDialog {
    id: dialog
    readonly property real stepUp: 1.1
    readonly property real stepDown: 0.9

    function scaled(factor) {
        return [Math.max(minimum, Math.round(valueAt(0) * factor)),
                Math.max(minimum, Math.round(valueAt(1) * factor))]
    }

    tools: [
        Button {
            text: qsTr("Swap")
            onClicked: dialog.setValues([dialog.valueAt(1), dialog.valueAt(0)])
        },
        Button {
            id: monitorButton
            text: qsTr("This Monitor")
            onClicked: {
                const size = DisplayMetrics.ScreenPixels(monitorButton)
                dialog.setValues([size.width, size.height])
            }
        },
        Loader {
            active: Theme.touchPlatform
            visible: active
            source: "SafeZoneButton.qml"
            onLoaded: item.dialog = dialog
        },
        Button {
            text: "÷"
            Accessible.name: qsTr("Divide")
            onClicked: dialog.setValues(dialog.scaled(dialog.stepDown))
        },
        Button {
            text: "×"
            Accessible.name: qsTr("Multiply")
            onClicked: dialog.setValues(dialog.scaled(dialog.stepUp))
        }
    ]
}
