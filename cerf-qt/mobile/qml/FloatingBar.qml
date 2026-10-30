import QtQuick
import QtQuick.Controls
import CerfStyle
import Cerfman

Item {
    id: bar
    required property GuestSurface surface
    required property EmulatorController emulator
    property real areaWidth: 0
    property real areaHeight: 0
    property bool stripShown: false
    property bool stripPaged: false
    property real stripProgress: 0
    signal stripRequested()

    component ChevronButton: OverlayButton {
        readonly property int chevronWidth: 22
        readonly property int chevronIconSize: 18

        implicitWidth: chevronWidth
        leftPadding: 0
        rightPadding: 0
        icon.width: chevronIconSize
        icon.height: chevronIconSize
        icon.color: Theme.overlayHandle
    }

    readonly property int barHeight: 52
    readonly property int handleIconSize: 22
    readonly property int slideMs: 220
    readonly property int edgeZone: 26

    property bool moved: false
    property bool bubble: false
    property int edge: Qt.TopEdge
    readonly property real bubbleInset: (width - height) / 2
    readonly property real minX: surface.safeMargins.left
    readonly property real maxX: areaWidth - surface.safeMargins.right - width
    readonly property real topY: surface.safeMargins.top + Theme.overlayTopGap
    readonly property real bottomY: areaHeight - surface.safeMargins.bottom - height
    readonly property real dockX: edge === Qt.LeftEdge ? minX - bubbleInset : maxX + bubbleInset
    readonly property real dockY: edge === Qt.TopEdge ? topY : bottomY
    readonly property bool sideEdge: edge === Qt.LeftEdge || edge === Qt.RightEdge

    x: (areaWidth - width) / 2
    y: topY
    width: row.implicitWidth
    height: barHeight
    containmentMask: body

    onXChanged: if (drag.active && bubble && sideEdge && Math.abs(x - dockX) > height) bubble = false
    onYChanged: if (drag.active && bubble && !sideEdge && Math.abs(y - dockY) > height) bubble = false
    onAreaWidthChanged: Qt.callLater(place)
    onAreaHeightChanged: Qt.callLater(place)

    Connections {
        target: bar.surface
        function onSafeMarginsChanged() {
            Qt.callLater(bar.place)
        }
    }

    DragHandler {
        id: drag
        property point finger
        onCentroidChanged: if (active) finger = centroid.scenePosition
        xAxis.minimum: bar.bubble ? bar.minX - bar.bubbleInset : bar.minX - bar.barHeight
        xAxis.maximum: bar.bubble ? bar.maxX + bar.bubbleInset : bar.maxX + bar.barHeight
        yAxis.minimum: bar.bubble ? bar.topY : bar.topY - bar.barHeight
        yAxis.maximum: bar.bubble ? bar.bottomY : bar.bottomY + bar.barHeight
        onActiveChanged: {
            if (active) {
                slide.stop()
                rise.stop()
                bar.moved = true
            } else {
                bar.settle()
            }
        }
    }

    TapHandler {
        enabled: bar.bubble
        onTapped: bar.openBubble()
    }

    NumberAnimation {
        id: slide
        target: bar
        property: "x"
        duration: bar.slideMs
        easing.type: Easing.OutCubic
    }

    NumberAnimation {
        id: rise
        target: bar
        property: "y"
        duration: bar.slideMs
        easing.type: Easing.OutCubic
    }

    Rectangle {
        id: body
        anchors.centerIn: parent
        width: bar.bubble ? bar.height : bar.width
        height: bar.height
        radius: height / 2
        clip: true
        color: Theme.overlayBar
        border.color: Theme.overlayBarBorder

        Behavior on width {
            NumberAnimation {
                duration: Theme.morphMs
                easing.type: Easing.OutCubic
            }
        }

        SymbolIcon {
            anchors.centerIn: parent
            visible: bar.bubble
            name: bar.edge === Qt.LeftEdge ? "chevron_right"
                : bar.edge === Qt.RightEdge ? "chevron_left"
                : bar.edge === Qt.TopEdge ? "keyboard_arrow_down" : "keyboard_arrow_up"
            size: bar.handleIconSize
            color: Theme.overlayHandle
        }

        Row {
            id: row
            anchors.centerIn: parent
            opacity: bar.bubble ? 0 : 1
            enabled: !bar.bubble
            spacing: 0
            leftPadding: Theme.spaceXS
            rightPadding: Theme.spaceXS

            ChevronButton {
                icon.source: IconSources.Icon("chevron_left")
                Accessible.name: qsTr("Hide the bar to the left")
                onClicked: bar.bubbleTo(Qt.LeftEdge)
            }
            OverlayButton {
                visible: bar.surface.keyboardButton
                icon.source: IconSources.Icon("keyboard")
                onClicked: bar.surface.ToggleKeyboard()
            }
            OverlayButton {
                visible: bar.emulator.hudAvailable
                icon.source: IconSources.Icon("gamepad")
                active: bar.emulator.hudShown
                onClicked: bar.emulator.ToggleHud()
            }
            OverlayButton {
                icon.source: IconSources.Icon("widgets")
                active: bar.stripShown
                onClicked: bar.stripRequested()

                PageDots {
                    anchors.horizontalCenter: parent.horizontalCenter
                    anchors.bottom: parent.bottom
                    anchors.bottomMargin: Theme.spaceXS
                    visible: bar.stripShown && bar.stripPaged
                    progress: bar.stripProgress
                }
            }
            OverlayButton {
                id: pointer
                visible: bar.surface.pointerMenu
                icon.source: bar.surface.pointerIcon
                onClicked: {
                    const at = pointer.mapToItem(bar.parent, 0, pointer.height)
                    bar.emulator.OpenPointerMenu(at.x, at.y)
                }
            }
            OverlayButton {
                id: gear
                icon.source: IconSources.settingsIcon
                onClicked: {
                    const at = gear.mapToItem(bar.parent, 0, gear.height)
                    bar.emulator.OpenGearMenu(at.x, at.y)
                }
            }
            ChevronButton {
                icon.source: IconSources.Icon("chevron_right")
                Accessible.name: qsTr("Hide the bar to the right")
                onClicked: bar.bubbleTo(Qt.RightEdge)
            }
        }
    }

    function clampX(value) {
        return Math.max(minX, Math.min(value, maxX))
    }

    function clampBubbleX(value) {
        return Math.max(minX - bubbleInset, Math.min(value, maxX + bubbleInset))
    }

    function clampY(value) {
        return Math.max(topY, Math.min(value, bottomY))
    }

    function move(toX, toY) {
        moved = true
        slide.stop()
        rise.stop()
        slide.to = toX
        rise.to = toY
        slide.start()
        rise.start()
    }

    function bubbleTo(toEdge) {
        edge = toEdge
        bubble = true
        move(sideEdge ? dockX : clampBubbleX(x), sideEdge ? clampY(y) : dockY)
    }

    function openBubble() {
        bubble = false
        move(clampX(x), clampY(y))
    }

    function settle() {
        if (bubble) {
            move(sideEdge ? dockX : x, sideEdge ? y : dockY)
            return
        }
        const finger = drag.finger
        const gaps = [finger.x, areaWidth - finger.x, finger.y, areaHeight - finger.y]
        const edges = [Qt.LeftEdge, Qt.RightEdge, Qt.TopEdge, Qt.BottomEdge]
        let nearest = 0
        for (let i = 1; i < gaps.length; ++i) {
            if (gaps[i] < gaps[nearest])
                nearest = i
        }
        if (gaps[nearest] < edgeZone)
            bubbleTo(edges[nearest])
        else
            move(clampX(x), clampY(y))
    }

    function place() {
        if (!moved)
            return
        slide.stop()
        rise.stop()
        if (bubble) {
            x = sideEdge ? dockX : clampBubbleX(x)
            y = sideEdge ? clampY(y) : dockY
        } else {
            x = clampX(x)
            y = clampY(y)
        }
    }
}
