import QtQuick
import QtQuick.Controls
import CerfStyle

ToolButton {
    id: button
    property bool pending: false

    icon.source: IconSources.Icon("notifications")
    Accessible.name: qsTr("Notifications")

    UnreadDot {
        visible: button.pending
        anchors.horizontalCenter: parent.horizontalCenter
        anchors.horizontalCenterOffset: button.icon.width / 2
        anchors.verticalCenter: parent.verticalCenter
        anchors.verticalCenterOffset: -button.icon.height / 2
    }
}
