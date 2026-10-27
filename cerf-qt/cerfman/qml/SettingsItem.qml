import QtQuick
import QtQuick.Layouts
import CerfStyle

ColumnLayout {
    id: item
    property bool divider: true
    default property alias body: frame.data

    Layout.fillWidth: true
    spacing: 0

    Divider {
        Layout.fillWidth: true
        visible: item.divider
    }
    ColumnLayout {
        id: frame
        Layout.fillWidth: true
        Layout.leftMargin: Theme.spaceXL
        Layout.rightMargin: Theme.spaceXL
        Layout.topMargin: Theme.spaceM
        Layout.bottomMargin: Theme.spaceM
        spacing: 0
    }
}
