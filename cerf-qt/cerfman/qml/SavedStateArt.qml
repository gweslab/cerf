import QtQuick
import CerfStyle

Item {
    id: art
    readonly property int diskSize: 112
    readonly property int badgeSize: 52
    readonly property int markSize: 36
    readonly property int shakeAngle: 8
    readonly property int popMs: 320
    readonly property int shakeMs: 70
    readonly property int holdMs: 1100
    readonly property int fadeMs: 300
    readonly property int restMs: 700

    SymbolIcon {
        id: disk
        anchors.centerIn: parent
        name: "save"
        size: art.diskSize
    }
    Rectangle {
        id: badge
        anchors.right: disk.right
        anchors.bottom: disk.bottom
        width: art.badgeSize
        height: art.badgeSize
        radius: art.badgeSize / 2
        color: Theme.notice
        opacity: 0

        SymbolIcon {
            anchors.centerIn: parent
            name: "close"
            size: art.markSize
            color: Theme.noticeMark
        }
    }
    SequentialAnimation {
        running: art.visible
        loops: Animation.Infinite

        PauseAnimation {
            duration: art.restMs
        }
        ParallelAnimation {
            NumberAnimation {
                target: badge
                property: "scale"
                from: 0
                to: 1
                duration: art.popMs
                easing.type: Easing.OutBack
            }
            NumberAnimation {
                target: badge
                property: "opacity"
                from: 0
                to: 1
                duration: art.popMs
            }
        }
        NumberAnimation {
            target: disk
            property: "rotation"
            to: -art.shakeAngle
            duration: art.shakeMs
        }
        NumberAnimation {
            target: disk
            property: "rotation"
            to: art.shakeAngle
            duration: art.shakeMs * 2
        }
        NumberAnimation {
            target: disk
            property: "rotation"
            to: -art.shakeAngle
            duration: art.shakeMs * 2
        }
        NumberAnimation {
            target: disk
            property: "rotation"
            to: 0
            duration: art.shakeMs
        }
        PauseAnimation {
            duration: art.holdMs
        }
        NumberAnimation {
            target: badge
            property: "opacity"
            to: 0
            duration: art.fadeMs
        }
    }
}
