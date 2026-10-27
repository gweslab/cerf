import QtQuick
import QtQuick.Controls
import CerfStyle

Menu {
    id: menu
    property var row: null
    readonly property string name: row !== null ? row.name : ""
    signal launchRequested(string name)
    signal discardRequested(string name)
    signal updateRequested(string name)
    signal openDirectoryRequested(string name)
    signal removeRequested(string name)
    signal renameRequested(string name)
    signal propertiesRequested(string name)

    MenuItem {
        text: menu.row !== null ? menu.row.launchLabel : ""
        onTriggered: menu.launchRequested(menu.name)
    }
    MenuItem {
        visible: menu.row !== null && menu.row.saved
        text: qsTr("Discard State")
        onTriggered: menu.discardRequested(menu.name)
    }
    MenuItem {
        visible: menu.row !== null && menu.row.updatable
        text: qsTr("Update")
        onTriggered: menu.updateRequested(menu.name)
    }
    MenuSeparator {
        visible: !Theme.touchPlatform
    }
    MenuItem {
        visible: !Theme.touchPlatform
        text: qsTr("Open device directory")
        onTriggered: menu.openDirectoryRequested(menu.name)
    }
    MenuSeparator {}
    MenuItem {
        enabled: menu.row !== null && menu.row.removable
        text: qsTr("Delete")
        onTriggered: menu.removeRequested(menu.name)
    }
    MenuItem {
        text: qsTr("Rename…")
        onTriggered: menu.renameRequested(menu.name)
    }
    MenuSeparator {}
    MenuItem {
        text: qsTr("Properties…")
        onTriggered: menu.propertiesRequested(menu.name)
    }
}
