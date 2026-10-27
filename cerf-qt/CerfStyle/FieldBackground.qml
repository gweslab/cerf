import QtQuick
import QtQuick.Controls.Material

Rectangle {
    required property Item control
    readonly property int fieldWidth: 120

    implicitWidth: fieldWidth
    implicitHeight: Theme.fieldHeight
    radius: Theme.radius
    color: Theme.cardBg
    opacity: control.enabled ? 1 : 0.6
    border.width: control.activeFocus ? Theme.focusLine : Theme.hairline
    border.color: control.activeFocus ? control.Material.accentColor : Theme.divider
}
