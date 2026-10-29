import QtQuick
import QtQuick.Controls
import CerfStyle

Column {
    id: header
    property bool mobile: false
    property bool stacked: false
    property string title: ""
    property string actionName: ""
    property bool actionEnabled: true
    property bool searchable: false
    readonly property string searchText: mobile ? bar.searchText : filterBar.searchText
    default property alias filters: filterBar.content
    signal back()
    signal action()

    PageBar {
        id: bar
        width: parent.width
        visible: header.mobile
        title: header.title
        searchable: header.searchable
        actionVisible: true
        actionName: header.actionName
        actionEnabled: header.actionEnabled
        onBack: header.back()
        onAction: header.action()
    }
    FilterBar {
        id: filterBar
        width: parent.width
        visible: header.searchable
        searchVisible: !header.mobile
        stacked: header.stacked
    }
}
