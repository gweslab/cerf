import QtQuick
import CerfStyle

Row {
    id: dots
    property real progress: 0
    readonly property real dim: 0.35

    spacing: Theme.spaceXS

    Repeater {
        model: 2
        delegate: Rectangle {
            required property int index
            width: Theme.spaceXS
            height: Theme.spaceXS
            radius: width / 2
            color: Theme.overlayIcon
            opacity: dots.dim + (1 - dots.dim) * (index === 0 ? 1 - dots.progress : dots.progress)
        }
    }
}
