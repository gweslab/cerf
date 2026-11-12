import QtQuick
import QtQuick.Window
import CerfStyle
import Cerfman

Rectangle {
    id: box
    property alias view: view
    property bool expanded: false
    property rect area: Qt.rect(0, 0, 0, 0)
    property real bottomLimit: area.y + area.height
    property real offsetX: 0
    property real offsetY: 0
    property real dragBaseX: 0
    property real dragBaseY: 0
    readonly property int collapsedWidth: 128
    readonly property real surfaceW: Math.max(1, view.surfaceWidth)
    readonly property real surfaceH: Math.max(1, view.surfaceHeight)
    readonly property real nativeW: surfaceW / Screen.devicePixelRatio
    readonly property real nativeH: surfaceH / Screen.devicePixelRatio
    readonly property real fitScale: Math.min(1, area.width / nativeW, area.height / nativeH)
    readonly property real expandedW: nativeW * fitScale
    readonly property real expandedH: nativeH * fitScale
    readonly property real collapsedH: collapsedWidth * surfaceH / surfaceW

    width: expanded ? expandedW : collapsedWidth
    height: expanded ? expandedH : collapsedH
    x: expanded ? clampX(area.x + (area.width - width) / 2 + offsetX)
                : area.x + area.width - width - Theme.spaceL
    y: expanded ? clampY(area.y + (area.height - height) / 2 + offsetY)
                : Math.min(area.y + area.height, bottomLimit) - height - Theme.spaceL
    radius: Theme.radius
    color: Theme.screenBg
    border.color: Theme.overlayBarBorder
    border.width: Theme.hairline

    function clampX(value) {
        return Math.max(area.x, Math.min(value, area.x + area.width - width))
    }

    function clampY(value) {
        return Math.max(area.y, Math.min(value, area.y + area.height - height))
    }

    Behavior on width {
        enabled: !drag.active
        NumberAnimation { duration: Theme.morphMs; easing.type: Easing.OutCubic }
    }
    Behavior on height {
        enabled: !drag.active
        NumberAnimation { duration: Theme.morphMs; easing.type: Easing.OutCubic }
    }
    Behavior on x {
        enabled: !drag.active
        NumberAnimation { duration: Theme.morphMs; easing.type: Easing.OutCubic }
    }
    Behavior on y {
        enabled: !drag.active
        NumberAnimation { duration: Theme.morphMs; easing.type: Easing.OutCubic }
    }

    ExternalDisplayView {
        id: view
        anchors.fill: parent
        anchors.margins: box.border.width
        fillColor: Theme.screenBg
    }

    TapHandler {
        onTapped: {
            box.offsetX = 0
            box.offsetY = 0
            box.expanded = !box.expanded
        }
    }

    DragHandler {
        id: drag
        target: null
        enabled: box.expanded
        onActiveChanged: {
            if (!active) {
                box.offsetX = box.x - (box.area.x + (box.area.width - box.width) / 2)
                box.offsetY = box.y - (box.area.y + (box.area.height - box.height) / 2)
                return
            }
            box.dragBaseX = box.offsetX
            box.dragBaseY = box.offsetY
        }
        onTranslationChanged: {
            box.offsetX = box.dragBaseX + translation.x
            box.offsetY = box.dragBaseY + translation.y
        }
    }
}
