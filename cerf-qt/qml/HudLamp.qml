import QtQuick
import QtQuick.Shapes
import CerfStyle

Item {
    id: root
    property var lamps: []
    property string shape

    readonly property real glowPart: 1.9
    readonly property real floorPart: 0.84
    readonly property real domePart: 0.7
    readonly property real lightX: 0.38
    readonly property real lightY: 0.32
    readonly property real lightReach: 0.78
    readonly property real domeMiddle: 0.45
    readonly property real domeLighter: 1.8
    readonly property real domeDarker: 2.4
    readonly property real highlightPart: 0.3
    readonly property real highlightX: 0.2
    readonly property real highlightY: 0.14
    readonly property real highlightAspect: 0.6
    readonly property real highlightTilt: -35
    readonly property real litHighlight: 0.75
    readonly property real darkHighlight: 0.3
    readonly property real glowAlpha: 0.5

    LampLight {
        id: light
        lamps: root.lamps
    }

    Loader {
        anchors.fill: parent
        sourceComponent: root.shape === "circle" ? circle : root.shape === "disc" ? disc : null
    }

    Component {
        id: disc
        HudLedFace {
            base: light.color
            lit: light.lit
        }
    }

    Component {
        id: circle
        Item {
            id: led
            readonly property real side: Math.min(width, height)
            readonly property color dome: light.color
            readonly property bool glowing: light.lit

            HudDisc {
                visible: led.glowing
                anchors.centerIn: parent
                width: led.side * root.glowPart
                height: width
                gradient: RadialGradient {
                    centerX: led.side * root.glowPart / 2
                    centerY: centerX
                    centerRadius: centerX
                    focalX: centerX
                    focalY: centerY
                    GradientStop {
                        position: 0
                        color: Qt.rgba(led.dome.r, led.dome.g, led.dome.b, root.glowAlpha)
                    }
                    GradientStop {
                        position: 1
                        color: Qt.rgba(led.dome.r, led.dome.g, led.dome.b, 0)
                    }
                }
            }
            Rectangle {
                anchors.centerIn: parent
                width: led.side
                height: width
                radius: width / 2
                gradient: Gradient {
                    GradientStop {
                        position: 0
                        color: Theme.lampCutoutShade
                    }
                    GradientStop {
                        position: 1
                        color: Theme.lampCutoutLight
                    }
                }
            }
            Rectangle {
                anchors.centerIn: parent
                width: led.side * root.floorPart
                height: width
                radius: width / 2
                color: Theme.lampFloor
            }
            HudDisc {
                id: domeDisc
                anchors.centerIn: parent
                width: led.side * root.domePart
                height: width
                gradient: RadialGradient {
                    centerX: domeDisc.width * root.lightX
                    centerY: domeDisc.height * root.lightY
                    centerRadius: domeDisc.width * root.lightReach
                    focalX: centerX
                    focalY: centerY
                    GradientStop {
                        position: 0
                        color: Qt.lighter(led.dome, root.domeLighter)
                    }
                    GradientStop {
                        position: root.domeMiddle
                        color: led.dome
                    }
                    GradientStop {
                        position: 1
                        color: Qt.darker(led.dome, root.domeDarker)
                    }
                }
            }
            Rectangle {
                x: domeDisc.x + domeDisc.width * root.highlightX
                y: domeDisc.y + domeDisc.height * root.highlightY
                width: domeDisc.width * root.highlightPart
                height: width * root.highlightAspect
                radius: height / 2
                rotation: root.highlightTilt
                color: Theme.lampHighlight
                opacity: led.glowing ? root.litHighlight : root.darkHighlight
            }
        }
    }
}
