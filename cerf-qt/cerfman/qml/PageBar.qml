import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

ToolBar {
    id: bar
    property string title: ""
    property bool backVisible: true
    property bool actionVisible: false
    property bool actionEnabled: true
    property string actionName: ""
    property bool searchable: false
    readonly property alias searchText: search.text
    signal back()
    signal action()

    RowLayout {
        anchors.fill: parent
        spacing: 0

        ToolButton {
            visible: bar.backVisible
            icon.source: IconSources.Icon("arrow_back")
            Accessible.name: qsTr("Back")
            onClicked: bar.back()
        }
        TitleLabel {
            Layout.fillWidth: true
            Layout.leftMargin: bar.backVisible ? 0 : Theme.spaceXXXL
            visible: !bar.searchable
            level: TitleLabel.Bar
            text: bar.title
            elide: Text.ElideRight
        }
        SearchBox {
            id: search
            Layout.fillWidth: true
            Layout.leftMargin: bar.backVisible ? 0 : Theme.spaceXL
            Layout.rightMargin: bar.actionVisible ? 0 : Theme.spaceXL
            visible: bar.searchable
        }
        ToolButton {
            visible: bar.actionVisible
            enabled: bar.actionEnabled
            icon.source: IconSources.Icon("check")
            Accessible.name: bar.actionName
            onClicked: bar.action()
        }
    }
}
