import QtQuick
import QtQuick.Controls.Material
import CerfStyle

Item {
    id: art
    readonly property int crossLength: 104
    readonly property int ringSize: 44
    readonly property int rippleSize: 64
    readonly property int pointerSize: 56
    readonly property int clickMs: 900
    readonly property int restMs: 700

    Rectangle {
        anchors.centerIn: parent
        width: art.crossLength
        height: Theme.focusLine
        color: Material.foreground
    }
    Rectangle {
        anchors.centerIn: parent
        width: Theme.focusLine
        height: art.crossLength
        color: Material.foreground
    }
    Rectangle {
        anchors.centerIn: parent
        width: art.ringSize
        height: art.ringSize
        radius: art.ringSize / 2
        color: Theme.noFill
        border.width: Theme.focusLine
        border.color: Material.foreground
    }
    Rectangle {
        id: ripple
        anchors.centerIn: parent
        width: art.rippleSize
        height: art.rippleSize
        radius: art.rippleSize / 2
        color: Theme.noFill
        border.width: Theme.focusLine
        border.color: Material.accentColor
        opacity: 0

        SequentialAnimation {
            running: art.visible
            loops: Animation.Infinite

            ParallelAnimation {
                NumberAnimation {
                    target: ripple
                    property: "scale"
                    from: 0.2
                    to: 1
                    duration: art.clickMs
                    easing.type: Easing.OutCubic
                }
                NumberAnimation {
                    target: ripple
                    property: "opacity"
                    from: 1
                    to: 0
                    duration: art.clickMs
                    easing.type: Easing.InCubic
                }
            }
            PauseAnimation {
                duration: art.restMs
            }
        }
    }
    SymbolIcon {
        anchors.left: parent.horizontalCenter
        anchors.leftMargin: -art.pointerSize * IconSources.cursorHotspot.x
        anchors.top: parent.verticalCenter
        anchors.topMargin: -art.pointerSize * IconSources.cursorHotspot.y
        name: IconSources.cursorSymbol
        size: art.pointerSize
    }
}
