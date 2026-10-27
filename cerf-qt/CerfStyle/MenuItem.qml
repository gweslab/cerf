import QtQuick
import QtQuick.Controls.Material
import QtQuick.Controls.Material as M

M.MenuItem {
    id: control
    readonly property real leadingRoom: checkable && indicator ? indicator.width + spacing : 0
    readonly property real trailingRoom: subMenu && arrow ? arrow.width + spacing : 0
    height: visible ? implicitHeight : 0

    contentItem: Text {
        leftPadding: control.mirrored ? control.trailingRoom : control.leadingRoom
        rightPadding: control.mirrored ? control.leadingRoom : control.trailingRoom
        text: control.text
        font: control.font
        color: enabled ? control.Material.foreground : control.Material.hintTextColor
        wrapMode: Text.Wrap
        verticalAlignment: Text.AlignVCenter
        horizontalAlignment: control.mirrored ? Text.AlignRight : Text.AlignLeft
    }
}
