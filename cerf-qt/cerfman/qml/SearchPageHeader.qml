import QtQuick
import QtQuick.Controls
import CerfStyle

Column {
    id: header
    property bool mobile: false
    property string title: ""
    property string actionName: ""
    property bool actionEnabled: true
    property bool searchable: false
    readonly property alias searchText: search.text
    default property alias filters: bar.content
    signal back()
    signal action()

    PageBar {
        width: parent.width
        visible: header.mobile
        title: header.title
        actionVisible: true
        actionName: header.actionName
        actionEnabled: header.actionEnabled
        onBack: header.back()
        onAction: header.action()
    }
    FilterBar {
        id: bar
        width: parent.width
        visible: header.searchable

        SearchBox {
            id: search
            width: Math.min(Theme.searchWidth, parent.width)
        }
    }
}
