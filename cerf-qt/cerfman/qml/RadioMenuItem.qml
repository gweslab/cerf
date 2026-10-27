import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material

MenuItem {
    id: item
    readonly property color markColor: !enabled ? Material.hintTextColor
                                     : checked ? Material.accentColor : Material.secondaryTextColor

    checkable: true
    indicator: Rectangle {
        anchors.verticalCenter: item.verticalCenter
        anchors.left: item.mirrored ? undefined : item.left
        anchors.right: item.mirrored ? item.right : undefined
        anchors.leftMargin: item.leftPadding
        anchors.rightMargin: item.rightPadding
        implicitWidth: Theme.radioSize
        implicitHeight: Theme.radioSize
        radius: width / 2
        color: Theme.noFill
        border.width: Theme.focusLine
        border.color: item.markColor

        Rectangle {
            anchors.centerIn: parent
            width: Theme.radioDotSize
            height: Theme.radioDotSize
            radius: width / 2
            color: item.markColor
            visible: item.checked
        }
    }
}
