import QtQuick
import QtQuick.Effects
import QtQuick.Shapes
import CerfStyle

Item {
    id: root
    property color base
    property bool lit: false

    readonly property real lipPart: 0.12
    readonly property real edgeLighter: 1.6
    readonly property real bottomDarker: 1.5
    readonly property real litAlpha: 0.85
    readonly property real darkAlpha: 0.75
    readonly property real glowPart: 0.35

    readonly property real alpha: lit ? litAlpha : darkAlpha

    function tinted(color) {
        return Qt.rgba(color.r, color.g, color.b, alpha)
    }

    HudDisc {
        anchors.fill: parent
        gradient: LinearGradient {
            x1: 0
            y1: 0
            x2: 0
            y2: root.height
            GradientStop {
                position: 0
                color: root.tinted(Qt.lighter(root.base, root.edgeLighter))
            }
            GradientStop {
                position: root.lipPart
                color: root.tinted(root.base)
            }
            GradientStop {
                position: 1
                color: root.tinted(Qt.darker(root.base, root.bottomDarker))
            }
        }
        layer.enabled: root.lit
        layer.effect: MultiEffect {
            shadowEnabled: true
            shadowColor: root.base
            shadowBlur: 1
            shadowHorizontalOffset: 0
            shadowVerticalOffset: 0
            blurMax: Math.max(1, Math.round(Math.min(root.width, root.height) * root.glowPart))
        }
    }
}
