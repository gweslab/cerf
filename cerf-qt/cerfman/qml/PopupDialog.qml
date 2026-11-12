import QtQuick
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
    leftMargin: Theme.touchPlatform ? WindowInsets.leftMargin : undefined
    topMargin: Theme.touchPlatform ? WindowInsets.topMargin : undefined
    rightMargin: Theme.touchPlatform ? WindowInsets.rightMargin : undefined
    bottomMargin: Theme.touchPlatform ? WindowInsets.bottomMargin : undefined
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
