import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle
import Cerfman

Menu {
    id: menu
    property var model: []
    property var subMenus: []
    signal picked(int id)
    signal branchClosed()

    WindowInsets.gap: Theme.spaceM

    function treeVisible() {
        return menu.visible || menu.subMenus.some(sub => sub.treeVisible())
    }

    function closeTree() {
        menu.subMenus.forEach(sub => sub.closeTree())
        menu.close()
    }

    function build() {
        const subs = []
        for (const entry of model) {
            if (entry.separator) {
                addItem(separatorComponent.createObject(menu.contentItem))
            } else if (entry.row.length > 0) {
                addItem(rowComponent.createObject(menu.contentItem, {"buttons": entry.row}))
            } else if (entry.submenu.length > 0) {
                const sub = Qt.createComponent("EmulatorMenu.qml").createObject(menu, {
                    "title": entry.text,
                    "model": entry.submenu,
                    "enabled": entry.enabled
                })
                sub.picked.connect(id => menu.picked(id))
                sub.branchClosed.connect(menu.branchClosed)
                subs.push(sub)
                addMenu(sub)
            } else {
                addItem((entry.radio ? radioItemComponent : itemComponent).createObject(menu.contentItem, {
                    "text": entry.text,
                    "enabled": entry.enabled && entry.id >= 0,
                    "checkable": entry.checkable,
                    "checked": entry.checked,
                    "itemId": entry.id
                }))
            }
        }
        subMenus = subs
    }

    Component.onCompleted: build()
    onClosed: branchClosed()

    Component {
        id: itemComponent
        MenuItem {
            property int itemId: -1
            onTriggered: menu.picked(itemId)
        }
    }

    Component {
        id: radioItemComponent
        RadioMenuItem {
            property int itemId: -1
            onTriggered: menu.picked(itemId)
        }
    }

    Component {
        id: separatorComponent
        MenuSeparator {}
    }

    Component {
        id: rowComponent
        RowLayout {
            id: buttonRow
            property var buttons: []
            spacing: 0

            Repeater {
                model: buttonRow.buttons
                ToolButton {
                    required property var modelData
                    Layout.fillWidth: true
                    icon.source: IconSources.Icon(modelData.icon)
                    enabled: modelData.enabled && modelData.id >= 0
                    Accessible.name: modelData.text
                    onClicked: menu.picked(modelData.id)
                }
            }
        }
    }
}
