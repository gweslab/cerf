import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

ToolBar {
    id: bar
    required property Action newAction
    property alias query: search.text
    readonly property int searchMinimumWidth: 120
    signal settings()

    RowLayout {
        anchors.fill: parent
        anchors.rightMargin: Theme.spaceM
        spacing: 0

        ToolButton {
            action: bar.newAction
        }
        ToolButton {
            text: qsTr("Settings")
            icon.source: IconSources.settingsIcon
            onClicked: bar.settings()
        }
        Item {
            Layout.fillWidth: true
        }
        SearchBox {
            id: search
            Layout.fillWidth: true
            Layout.minimumWidth: bar.searchMinimumWidth
            Layout.maximumWidth: Theme.searchWidth
        }
    }
}
