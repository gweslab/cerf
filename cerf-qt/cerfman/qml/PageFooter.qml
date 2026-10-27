import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

Pane {
    id: footer
    property bool stacked: false
    property alias leading: leadingRow.data
    default property alias trailing: trailingRow.data

    padding: Theme.spaceXL

    background: Rectangle {
        color: Theme.barBg

        Divider {
            width: parent.width
        }
    }

    GridLayout {
        anchors.fill: parent
        columns: footer.stacked ? 1 : 2
        columnSpacing: Theme.spaceXL
        rowSpacing: Theme.spaceM

        RowLayout {
            id: leadingRow
            visible: children.length > 0
            spacing: Theme.spaceXL
        }
        RowLayout {
            id: trailingRow
            Layout.fillWidth: true
            spacing: Theme.spaceS

            Item {
                Layout.fillWidth: true
            }
        }
    }
}
