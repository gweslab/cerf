import QtQuick
import QtQuick.Controls

MenuItem {
    id: item
    property bool unread: false

    UnreadDot {
        visible: item.unread
        x: (item.leftPadding - width) / 2
        anchors.verticalCenter: parent.verticalCenter
    }
}
