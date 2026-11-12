import QtQuick
import CerfStyle

ToolButton {
    property bool active: false

    focusPolicy: Qt.NoFocus
    icon.color: active ? Theme.overlayActive : Theme.overlayIcon
}
