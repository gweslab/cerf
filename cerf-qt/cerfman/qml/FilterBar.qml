import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

Pane {
    id: bar
    property bool searchVisible: false
    property bool stacked: false
    readonly property alias searchText: search.text
    default property alias content: filters.data

    padding: Theme.spaceM

    background: Rectangle {
        color: Theme.barBg
    }

    GridLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        columns: bar.stacked ? 1 : 2
        columnSpacing: Theme.spaceM
        rowSpacing: Theme.spaceM

        ColumnLayout {
            id: filters
            Layout.fillWidth: true
            spacing: Theme.spaceM
        }
        SearchBox {
            id: search
            Layout.fillWidth: bar.stacked
            Layout.preferredWidth: Theme.searchWidth
            visible: bar.searchVisible
        }
    }
}
