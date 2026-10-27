import QtQuick
import QtQuick.Controls
import CerfStyle

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
}
