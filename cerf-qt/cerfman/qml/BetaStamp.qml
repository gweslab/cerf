import QtQuick
import CerfStyle

Item {
    id: art
    readonly property int stampWidth: 140
    readonly property int stampHeight: 64
    readonly property int stampLine: 4
    readonly property int stampTilt: -14

    Rectangle {
        anchors.centerIn: parent
        width: art.stampWidth
        height: art.stampHeight
        rotation: art.stampTilt
        radius: Theme.radius
        color: Theme.noFill
        border.width: art.stampLine
        border.color: Theme.danger

        StampLabel {
            anchors.centerIn: parent
            text: qsTr("BETA")
        }
    }
}
