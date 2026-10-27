import QtQuick
import CerfStyle

Rectangle {
    property bool hovered: false

    color: hovered ? Theme.cardHover : Theme.cardBg
    border.color: Theme.divider
    radius: Theme.radius
}
