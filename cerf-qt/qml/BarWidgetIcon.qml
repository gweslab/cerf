import QtQuick
import QtQuick.Shapes
import CerfStyle

Item {
    id: root
    property string kind
    property url source
    property int percent
    property bool unplugged
    property string level
    property bool failed
    property bool folderOn
    property real unit: 1

    readonly property real cx: Math.floor(width / unit / 2) * unit
    readonly property real cy: Math.floor(height / unit / 2) * unit
    readonly property int outline: 1
    readonly property int resourceInset: 4
    readonly property int batteryWidth: 18
    readonly property int batteryHeight: 11
    readonly property int batteryTipWidth: 2
    readonly property int batteryTipHalfHeight: 2
    readonly property int powerHalf: 5
    readonly property int powerLine: 2
    readonly property int prongWidth: 2
    readonly property var powerProngs: [[-2, -9, -5], [2, -9, -5], [0, 5, 9]]
    readonly property var boltPoints: [[0, -5], [-3, 1], [0, 1], [-1, 5], [3, -1], [0, -1], [0, -5]]
    readonly property var folderPoints: [[-8, 6], [-8, -6], [-2, -6], [0, -3], [8, -3], [8, 6], [-8, 6]]

    function u(value) {
        return value * unit
    }

    function polyline(points) {
        return points.map(p => Qt.point(cx + u(p[0]), cy + u(p[1])))
    }

    Loader {
        anchors.fill: parent
        sourceComponent: {
            switch (root.kind) {
            case "resource": return resource
            case "power": return power
            case "battery": return battery
            case "folder": return folder
            }
            return null
        }
    }

    Component {
        id: resource
        Item {
            Image {
                readonly property real side: Math.min(root.width, root.height) - root.u(root.resourceInset)
                anchors.centerIn: parent
                width: side
                height: side
                source: root.source
                sourceSize: Qt.size(side, side)
            }
        }
    }

    Component {
        id: power
        Item {
            readonly property color line: root.failed ? Theme.barPowerFail : Theme.barPowerOk
            Rectangle {
                x: root.cx - root.u(root.powerHalf)
                y: root.cy - root.u(root.powerHalf)
                width: root.u(2 * root.powerHalf)
                height: width
                color: root.failed ? Theme.barPowerFailFill : Theme.barPowerOkFill
                border.color: parent.line
                border.width: root.u(root.powerLine)
            }
            Repeater {
                model: root.powerProngs
                delegate: Rectangle {
                    required property var modelData
                    x: root.cx + root.u(modelData[0]) - root.u(root.prongWidth / 2)
                    y: root.cy + root.u(modelData[1])
                    width: root.u(root.prongWidth)
                    height: root.u(modelData[2] - modelData[1])
                    color: parent.line
                }
            }
        }
    }

    Component {
        id: battery
        Item {
            readonly property real bodyLeft: root.cx - root.u(Math.floor(root.batteryWidth / 2))
            readonly property real bodyTop: root.cy - root.u(Math.floor(root.batteryHeight / 2))
            readonly property real bodyWidth: root.u(2 * Math.floor(root.batteryWidth / 2))
            readonly property real bodyHeight: root.u(2 * Math.floor(root.batteryHeight / 2))
            Rectangle {
                x: parent.bodyLeft
                y: parent.bodyTop
                width: parent.bodyWidth
                height: parent.bodyHeight
                color: Theme.barBatteryBody
                border.color: Theme.barBatteryFrame
                border.width: root.u(root.outline)
            }
            Rectangle {
                x: parent.bodyLeft + parent.bodyWidth
                y: root.cy - root.u(root.batteryTipHalfHeight)
                width: root.u(root.batteryTipWidth)
                height: root.u(2 * root.batteryTipHalfHeight)
                color: Theme.barBatteryFrame
            }
            Rectangle {
                readonly property int fillWidth: Math.floor((root.batteryWidth - 2 * root.outline) * root.percent / 100)
                visible: fillWidth > 0
                x: parent.bodyLeft + root.u(root.outline)
                y: parent.bodyTop + root.u(root.outline)
                width: root.u(fillWidth)
                height: parent.bodyHeight - root.u(2 * root.outline)
                color: root.level === "critical" ? Theme.barBatteryCritical
                     : root.level === "low" ? Theme.barBatteryLow : Theme.barBatteryHigh
            }
            Shape {
                visible: !root.unplugged
                preferredRendererType: Shape.CurveRenderer
                ShapePath {
                    strokeColor: Theme.barBoltRim
                    strokeWidth: root.u(root.outline)
                    fillColor: Theme.barBolt
                    startX: root.cx + root.u(root.boltPoints[0][0])
                    startY: root.cy + root.u(root.boltPoints[0][1])
                    PathPolyline { path: root.polyline(root.boltPoints) }
                }
            }
        }
    }

    Component {
        id: folder
        Shape {
            preferredRendererType: Shape.CurveRenderer
            ShapePath {
                strokeColor: Theme.noFill
                fillColor: root.folderOn ? Theme.barFolderOn : Theme.barFolderOff
                startX: root.cx + root.u(root.folderPoints[0][0])
                startY: root.cy + root.u(root.folderPoints[0][1])
                PathPolyline { path: root.polyline(root.folderPoints) }
            }
        }
    }
}
