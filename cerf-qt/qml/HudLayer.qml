import QtQuick
import QtQuick.Shapes
import CerfStyle

Item {
    id: root
    property QtObject model
    property string uiFamily
    property real pixelScale: 1

    readonly property real labelPart: 0.42
    readonly property real iconPart: 0.5
    readonly property real labelRoomPart: 0.86
    readonly property real hintPart: 0.2
    readonly property real hintMaxPart: 0.3
    readonly property real radiusPart: 0.18
    readonly property real arrowReach: 0.8
    readonly property real arrowSize: 0.18
    readonly property real arrowDepth: 1.3
    readonly property real centerPart: 0.3
    readonly property int separatorPixels: 1
    readonly property int rimPixels: 2
    readonly property int keyShown: 1
    readonly property int keyPressed: 2

    function devicePixels(count) {
        return Math.max(1, Math.round(count * pixelScale)) / pixelScale
    }

    function hintSize(side, height) {
        const size = Math.min(Math.max(Theme.hudHintMinimumSize, Math.round(side * hintPart)),
                              Math.max(1, Math.round(side * hintMaxPart)))
        return Math.max(1, Math.min(size, Math.round(height)))
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
                    case "separator": return separator
                    case "button": return button
                    case "sticker": return sticker
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
                id: separator
                Item {
                    Rectangle {
                        width: Math.max(parent.width, root.devicePixels(root.separatorPixels))
                        height: Math.max(parent.height, root.devicePixels(root.separatorPixels))
                        color: Theme.hudSeparator
                    }
                }
            }

            Component {
                id: button
                Item {
                    Rectangle {
                        anchors.fill: parent
                        visible: cell.down
                        color: Theme.hudVeilDown
                    }
                    Rectangle {
                        anchors.fill: parent
                        visible: cell.latched
                        color: Theme.noFill
                        border.color: Theme.hudLatchRim
                        border.width: root.devicePixels(root.rimPixels)
                    }
                    HudFace {
                        anchors.fill: parent
                        symbol: cell.symbol
                        label: cell.label
                        family: root.uiFamily
                        ink: Theme.hudInk
                        iconSize: Math.max(1, Math.round(cell.side * root.iconPart))
                        labelSize: Math.max(1, Math.round(cell.side * root.labelPart))
                        labelRoom: Math.max(1, Math.round(cell.width * root.labelRoomPart))
                    }
                    HudLabel {
                        visible: cell.hint !== ""
                        anchors.left: parent.left
                        anchors.bottom: parent.bottom
                        width: parent.width
                        height: pixelSize
                        text: cell.hint
                        family: root.uiFamily
                        pixelSize: root.hintSize(cell.side, cell.height)
                        bold: false
                        ink: Theme.hudHint
                        horizontalAlignment: Text.AlignLeft
                        verticalAlignment: Text.AlignBottom
                    }
                }
            }

            Component {
                id: sticker
                HudFace {
                    readonly property real square: Math.max(1, Math.round(cell.side))
                    symbol: cell.symbol
                    label: cell.label
                    family: root.uiFamily
                    ink: Theme.hudHint
                    iconSize: square
                    labelSize: Math.max(1, Math.round(square * root.labelPart / root.iconPart))
                    labelRoom: cell.width
                }
            }

            Component {
                id: dpad
                Item {
                    id: pad
                    readonly property real padWidth: cell.circle ? cell.side : cell.width
                    readonly property real padHeight: cell.circle ? cell.side : cell.height
                    readonly property real half: Math.min(padWidth, padHeight) / 2
                    readonly property real arrow: half * root.arrowSize

                    function arrowPoints(side) {
                        const along = [[0, -1], [1, 0], [0, 1], [-1, 0]][side]
                        const reach = (along[0] !== 0 ? padWidth : padHeight) / 2 * root.arrowReach
                        const tipX = width / 2 + along[0] * reach
                        const tipY = height / 2 + along[1] * reach
                        const baseX = tipX - along[0] * arrow * root.arrowDepth
                        const baseY = tipY - along[1] * arrow * root.arrowDepth
                        const acrossX = -along[1] * arrow
                        const acrossY = along[0] * arrow
                        return [tipX, tipY, baseX + acrossX, baseY + acrossY, baseX - acrossX, baseY - acrossY]
                    }

                    Rectangle {
                        anchors.centerIn: parent
                        width: pad.padWidth
                        height: pad.padHeight
                        radius: cell.circle ? Math.floor(cell.side / 2)
                                            : Math.max(1, Math.round(cell.side * root.radiusPart))
                        color: Theme.hudVeil
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

                    Rectangle {
                        readonly property real centerRadius: Math.max(1, Math.round(pad.half * root.centerPart))
                        visible: cell.center !== 0
                        anchors.centerIn: parent
                        width: 2 * centerRadius
                        height: 2 * centerRadius
                        radius: centerRadius
                        color: cell.center === root.keyPressed ? Theme.hudVeilDown : Theme.hudVeilCenter
                    }
                }
            }
        }
    }

    component HudFace: Item {
        property url symbol
        property string label
        property string family
        property color ink
        property real iconSize
        property int labelSize
        property real labelRoom

        ControlIcon {
            anchors.centerIn: parent
            symbol: parent.symbol
            tint: parent.ink
            iconSize: Qt.size(parent.iconSize, parent.iconSize)
        }
        HudLabel {
            visible: parent.symbol.toString() === ""
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
