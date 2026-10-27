import QtQuick
import CerfStyle

GradientStop {
    required property real at
    readonly property color full: Theme.previewScrim

    position: at
    color: Qt.rgba(full.r, full.g, full.b, full.a * at * at * (3 - 2 * at))
}
