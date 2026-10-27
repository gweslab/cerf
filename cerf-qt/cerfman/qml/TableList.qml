import QtQuick
import QtQuick.Layouts
import CerfStyle

ColumnLayout {
    id: table
    property bool headerVisible: true
    property alias columns: header.data

    spacing: 0

    RowLayout {
        id: header
        Layout.fillWidth: true
        Layout.leftMargin: Theme.spaceXL
        Layout.rightMargin: Theme.spaceXL
        Layout.topMargin: Theme.spaceS
        Layout.bottomMargin: Theme.spaceS
        visible: table.headerVisible
        spacing: Theme.spaceXL
    }
}
