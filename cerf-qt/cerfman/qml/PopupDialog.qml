import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

Dialog {
    id: dialog
    property real preferredWidth: 520
    property alias rightToLeftButtons: buttonFlow.data

    parent: Overlay.overlay
    anchors.centerIn: parent
    modal: true
    WindowInsets.gap: Theme.spaceXXXL
    leftMargin: WindowInsets.leftMargin
    topMargin: WindowInsets.topMargin
    rightMargin: WindowInsets.rightMargin
    bottomMargin: WindowInsets.bottomMargin
    implicitWidth: preferredWidth

    footer: ColumnLayout {
        visible: buttonFlow.children.length > 0

        Flow {
            id: buttonFlow
            Layout.fillWidth: true
            Layout.margins: Theme.spaceXL
            layoutDirection: Qt.RightToLeft
            spacing: Theme.spaceS
        }
    }
}
