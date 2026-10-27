import QtQuick

HoverHandler {
    property int idleShape: Qt.ArrowCursor

    cursorShape: parent.hoveredLink !== "" ? Qt.PointingHandCursor : idleShape
}
