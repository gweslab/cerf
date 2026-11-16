import QtQuick
import CerfStyle

Rectangle {
    id: root
    property QtObject view
    property string monoFamily
    property point pixelScale: Qt.point(1, 1)
    property real insetLeft: 0
    property real insetTop: 0
    property real insetRight: 0
    property real insetBottom: 0

    readonly property int watermarkPixels: 1024
    readonly property real watermarkOpacity: 0.15
    readonly property int edgeMargin: 1

    color: Theme.canvasTabBg

    Image {
        anchors.centerIn: parent
        width: root.watermarkPixels / root.pixelScale.x
        height: root.watermarkPixels / root.pixelScale.y
        opacity: root.watermarkOpacity
        source: root.view.logo
        sourceSize: Qt.size(width, height)
    }

    ListView {
        id: lines
        anchors.fill: parent
        anchors.leftMargin: root.edgeMargin + root.insetLeft
        anchors.topMargin: root.edgeMargin + root.insetTop
        anchors.rightMargin: root.edgeMargin + root.insetRight
        anchors.bottomMargin: root.edgeMargin + root.insetBottom
        model: root.view.log
        interactive: false
        clip: true
        onCountChanged: positionViewAtEnd()
        onHeightChanged: positionViewAtEnd()

        delegate: Text {
            required text
            required property string tone
            width: ListView.view.width
            textFormat: Text.PlainText
            wrapMode: Text.WrapAnywhere
            font.family: root.monoFamily
            font.pixelSize: Theme.consoleFontSize
            font.bold: true
            color: tone === "error" ? Theme.consoleError : tone === "warning" ? Theme.consoleWarning : Theme.consoleText
        }
    }
}
