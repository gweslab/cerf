import QtQuick
import QtQuick.Shapes
import CerfStyle

Item {
    id: root
    property QtObject model
    property string uiFamily
    property string monoFamily
    property real pixelScale: 1

    readonly property real labelPart: 0.42
    readonly property real iconPart: 0.5
    readonly property real lampPart: 0.5
    readonly property real labelRoomPart: 0.86
    readonly property real radiusPart: 0.18
    readonly property real arrowReach: 0.8
    readonly property real arrowSize: 0.18
    readonly property real arrowDepth: 1.3
    readonly property real centerPart: 0.3
    readonly property real travelPart: 0.06
    readonly property real lipPart: 0.12
    readonly property real latchPart: 0.4
    readonly property int latchPixels: 2
    readonly property int seamPixels: 1
    readonly property int keyShown: 1
    readonly property int keyPressed: 2

    function devicePixels(count) {
        return Math.max(1, Math.round(count * pixelScale)) / pixelScale
    }

    Repeater {
        model: root.model
        delegate: Item {
            id: cell
            required property string kind
            required property real boxLeft
            required property real boxTop
            required property real boxWidth
            required property real boxHeight
            required property string label
            required property string symbol
            required property string hint
            required property bool down
            required property bool latched
            required property bool circle
            required property var arrows
            required property int center
            required property var lamps
            required property string lampShape
            required property bool mono
            required property real keyUnit

            readonly property real side: Math.min(width, height)

            x: boxLeft
            y: boxTop
            width: boxWidth
            height: boxHeight

            Loader {
                anchors.fill: parent
                sourceComponent: {
                    switch (cell.kind) {
                    case "band": return band
                    case "button": return button
                    case "sticker": return sticker
                    case "indicator": return indicator
                    case "dpad": return dpad
                    }
                    return null
                }
            }

            Component {
                id: band
                Rectangle {
                    color: Theme.hudBackdrop
                }
            }

            Component {
                id: button
                Item {
                    Keycap {
                        id: key
                        anchors.fill: parent
                        unit: cell.keyUnit
                        sunk: cell.down || cell.latched
                    }
                    HoverHandler {
                        id: hover
                    }
                    ToolTip {
                        visible: hover.hovered && cell.hint !== ""
                        text: qsTr("%1 on host").arg(cell.hint)
                        delay: Theme.tipDelayMs
                    }
                    Item {
                        y: key.faceTop
                        width: key.faceWidth
                        height: key.faceHeight
                        HudFace {
                            anchors.fill: parent
                            symbol: cell.symbol
                            label: cell.label
                            lamps: cell.lamps
                            lampShape: cell.lampShape
                            family: cell.mono ? root.monoFamily : root.uiFamily
                            ink: Theme.hudInk
                            iconSize: Math.max(1, Math.round(cell.side * root.iconPart))
                            lampSize: Math.max(1, Math.round(cell.side * root.lampPart))
                            labelSize: Math.max(1, Math.round(cell.side * root.labelPart))
                            labelRoom: Math.max(1, Math.round(cell.width * root.labelRoomPart))
                        }
                        Rectangle {
                            visible: cell.latched
                            anchors.horizontalCenter: parent.horizontalCenter
                            anchors.bottom: parent.bottom
                            anchors.bottomMargin: height
                            width: parent.width * root.latchPart
                            height: root.devicePixels(root.latchPixels)
                            radius: height / 2
                            color: Theme.overlayLatched
                        }
                    }
                }
            }

            Component {
                id: sticker
                HudFace {
                    readonly property real square: Math.max(1, Math.round(cell.side))
                    symbol: cell.symbol
                    label: cell.label
                    lamps: cell.lamps
                    lampShape: cell.lampShape
                    family: cell.mono ? root.monoFamily : root.uiFamily
                    ink: Theme.hudHint
                    iconSize: square
                    lampSize: Math.max(1, Math.round(square * root.lampPart))
                    labelSize: Math.max(1, Math.round(square * root.labelPart / root.iconPart))
                    labelRoom: cell.width
                }
            }

            Component {
                id: indicator
                HudLamp {
                    lamps: cell.lamps
                    shape: cell.lampShape
                }
            }

            Component {
                id: dpad
                Item {
                    Keycap {
                        id: base
                        anchors.centerIn: parent
                        width: cell.circle ? cell.side : cell.width
                        height: cell.circle ? cell.side : cell.height
                        unit: cell.keyUnit
                        round: cell.circle
                    }

                    Item {
                        id: pad
                        x: base.x
                        y: base.y + base.faceTop
                        width: base.faceWidth
                        height: base.faceHeight
                        readonly property real half: Math.min(width, height) / 2
                        readonly property real arrow: half * root.arrowSize

                        function arrowPoints(side) {
                            const along = [[0, -1], [1, 0], [0, 1], [-1, 0]][side]
                            const reach = (along[0] !== 0 ? width : height) / 2 * root.arrowReach
                            const tipX = width / 2 + along[0] * reach
                            const tipY = height / 2 + along[1] * reach
                            const baseX = tipX - along[0] * arrow * root.arrowDepth
                            const baseY = tipY - along[1] * arrow * root.arrowDepth
                            const acrossX = -along[1] * arrow
                            const acrossY = along[0] * arrow
                            return [tipX, tipY, baseX + acrossX, baseY + acrossY, baseX - acrossX, baseY - acrossY]
                        }

                        Repeater {
                            model: 4
                            delegate: Shape {
                                id: arrowShape
                                required property int index
                                readonly property var points: pad.arrowPoints(index)
                                visible: cell.arrows[index] !== 0
                                preferredRendererType: Shape.CurveRenderer
                                ShapePath {
                                    strokeColor: Theme.noFill
                                    fillColor: cell.arrows[arrowShape.index] === root.keyPressed ? Theme.hudInk
                                                                                                  : Theme.hudArrow
                                    startX: arrowShape.points[0]
                                    startY: arrowShape.points[1]
                                    PathLine {
                                        x: arrowShape.points[2]
                                        y: arrowShape.points[3]
                                    }
                                    PathLine {
                                        x: arrowShape.points[4]
                                        y: arrowShape.points[5]
                                    }
                                    PathLine {
                                        x: arrowShape.points[0]
                                        y: arrowShape.points[1]
                                    }
                                }
                            }
                        }

                        Keycap {
                            visible: cell.center !== 0
                            anchors.centerIn: parent
                            width: 2 * Math.max(1, Math.round(pad.half * root.centerPart))
                            height: width
                            unit: cell.keyUnit
                            round: true
                            sunk: cell.center === root.keyPressed
                        }
                    }
                }
            }
        }
    }

    component Keycap: Item {
        id: cap
        property bool sunk: false
        property bool round: false
        required property real unit
        readonly property real seam: root.devicePixels(root.seamPixels)
        readonly property real travel: root.devicePixels(unit * root.travelPart)
        readonly property real faceWidth: width - seam
        readonly property real faceHeight: height - seam - travel
        readonly property real faceTop: sunk ? travel : 0
        readonly property real corner: round ? Math.min(faceWidth, faceHeight) / 2
                                             : Math.max(1, Math.round(unit * root.radiusPart))

        Shape {
            visible: !cap.sunk
            preferredRendererType: Shape.CurveRenderer
            ShapePath {
                strokeColor: Theme.noFill
                fillColor: Theme.hudKeyShadow
                startX: 0
                startY: cap.faceHeight - cap.corner
                PathArc {
                    x: cap.corner
                    y: cap.faceHeight
                    radiusX: cap.corner
                    radiusY: cap.corner
                    direction: PathArc.Counterclockwise
                }
                PathLine {
                    x: cap.faceWidth - cap.corner
                    y: cap.faceHeight
                }
                PathArc {
                    x: cap.faceWidth
                    y: cap.faceHeight - cap.corner
                    radiusX: cap.corner
                    radiusY: cap.corner
                    direction: PathArc.Counterclockwise
                }
                PathLine {
                    x: cap.faceWidth
                    y: cap.faceHeight - cap.corner + cap.travel
                }
                PathArc {
                    x: cap.faceWidth - cap.corner
                    y: cap.faceHeight + cap.travel
                    radiusX: cap.corner
                    radiusY: cap.corner
                }
                PathLine {
                    x: cap.corner
                    y: cap.faceHeight + cap.travel
                }
                PathArc {
                    x: 0
                    y: cap.faceHeight - cap.corner + cap.travel
                    radiusX: cap.corner
                    radiusY: cap.corner
                }
                PathLine {
                    x: 0
                    y: cap.faceHeight - cap.corner
                }
            }
        }
        Rectangle {
            y: cap.faceTop
            width: cap.faceWidth
            height: cap.faceHeight
            radius: cap.corner
            gradient: Gradient {
                GradientStop {
                    position: 0
                    color: cap.sunk ? Theme.hudKeySunkEdge : Theme.hudKeyEdge
                }
                GradientStop {
                    position: root.lipPart
                    color: cap.sunk ? Theme.hudKeySunkTop : Theme.hudKeyTop
                }
                GradientStop {
                    position: 1
                    color: cap.sunk ? Theme.hudKeySunkBottom : Theme.hudKeyBottom
                }
            }
        }
    }

    component HudFace: Item {
        property url symbol
        property string label
        property var lamps: []
        property string lampShape
        property string family
        property color ink
        property real iconSize
        property real lampSize
        property int labelSize
        property real labelRoom

        HudLamp {
            visible: parent.lampShape !== ""
            anchors.centerIn: parent
            width: parent.lampSize
            height: parent.lampSize
            lamps: parent.lamps
            shape: parent.lampShape
        }
        ControlIcon {
            anchors.centerIn: parent
            symbol: parent.symbol
            tint: parent.ink
            iconSize: Qt.size(parent.iconSize, parent.iconSize)
        }
        HudLabel {
            visible: parent.symbol.toString() === "" && parent.lampShape === ""
            anchors.centerIn: parent
            width: parent.labelRoom
            height: parent.height
            text: parent.label
            family: parent.family
            pixelSize: parent.labelSize
            bold: true
            ink: parent.ink
        }
    }
}
