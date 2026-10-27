import QtQuick
import QtQuick.Controls
import QtQuick.Controls.Material
import CerfStyle

TextField {
    id: control
    property string hint: qsTr("Search")
    readonly property int iconSize: 18
    readonly property int boxWidth: 160

    leftPadding: iconRoom.width
    rightPadding: Theme.spaceXXL

    background: Rectangle {
        implicitWidth: control.boxWidth
        implicitHeight: Theme.fieldHeight
        radius: height / 2
        color: Theme.pageBg
        border.width: control.activeFocus ? Theme.focusLine : 0
        border.color: control.Material.accentColor

        Row {
            id: iconRoom
            anchors.left: parent.left
            anchors.verticalCenter: parent.verticalCenter
            leftPadding: Theme.spaceXL
            rightPadding: Theme.spaceM

            SymbolIcon {
                name: "search"
                size: control.iconSize
                color: Theme.dim
            }
        }
    }

    SecondaryLabel {
        anchors.left: parent.left
        anchors.leftMargin: control.leftPadding
        anchors.right: parent.right
        anchors.rightMargin: control.rightPadding
        anchors.verticalCenter: parent.verticalCenter
        visible: control.length === 0 && control.preeditText === ""
        text: control.hint
        font: control.font
        elide: Text.ElideRight
    }
}
