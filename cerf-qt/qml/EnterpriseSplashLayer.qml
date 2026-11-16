import QtQuick
import QtQuick.Layouts
import CerfStyle

Rectangle {
    id: root
    property QtObject view
    property int insetLeft: 0
    property int insetBottom: 0

    readonly property int logoMinWidth: 112
    readonly property int logoMaxWidth: 320
    readonly property real logoScreenPart: 0.5
    readonly property int badgeHeight: 28
    readonly property int logoWidth: Math.max(logoMinWidth,
                                              Math.min(logoMaxWidth, Math.floor(Math.min(width, height) * logoScreenPart)))

    color: Theme.canvasTabBg

    ColumnLayout {
        anchors.centerIn: parent
        spacing: Theme.spaceXXXL

        Image {
            Layout.alignment: Qt.AlignHCenter
            source: root.view.splashLogo
            sourceSize.width: root.logoWidth
        }
        BusyIndicator {
            Layout.alignment: Qt.AlignHCenter
            running: root.visible && !root.view.paused
        }
    }

    Image {
        anchors.left: parent.left
        anchors.bottom: parent.bottom
        anchors.leftMargin: Theme.spaceXL + root.insetLeft
        anchors.bottomMargin: Theme.spaceXL + root.insetBottom
        visible: root.view.splashBadge !== ""
        source: root.view.splashBadge
        sourceSize.height: root.badgeHeight
    }
}
