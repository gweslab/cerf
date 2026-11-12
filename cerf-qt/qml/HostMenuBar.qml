import QtQuick
import CerfStyle
import Cerfman

Item {
    id: bar
    property var titles: []
    property var contentFor: (index, menu) => []
    property bool hudButton: false
    property bool hudShown: false
    property bool hudAvailable: false
    readonly property int hudIconSize: 20
    signal picked(QtObject menu, int id)
    signal menuClosing()
    signal hudToggled()

    implicitHeight: Math.max(menus.height, hud.visible ? hud.implicitHeight : 0)

    Rectangle {
        anchors.fill: parent
        color: Theme.windowBarBg

        Rectangle {
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.bottom: parent.bottom
            height: Theme.hairline
            color: Theme.windowBarLine
        }
    }

    function refresh(menu) {
        if (!menu.visible)
            menu.rebuild(bar.contentFor(menu.barIndex, menu))
    }

    MenuBar {
        id: menus
        width: bar.width
        rightPadding: hud.visible ? hud.width : 0

        delegate: MenuBarItem {
            id: barItem

            HoverHandler {
                onPointChanged: {
                    if (hovered)
                        barItem.menu.noteOpenerPointer(barItem.mapToGlobal(point.position))
                }
                onHoveredChanged: {
                    if (!hovered)
                        barItem.menu.forgetOpenerPointer()
                }
            }

            onHighlightedChanged: {
                if (highlighted)
                    bar.refresh(menu)
            }
            onTriggered: bar.refresh(menu)
        }

        Instantiator {
            model: bar.titles
            delegate: EmulatorMenu {
                id: barMenu
                required property string modelData
                required property int index
                readonly property int barIndex: index
                title: modelData
                onPicked: id => bar.picked(barMenu, id)
                onAboutToHide: bar.menuClosing()
            }
            onObjectAdded: (index, object) => menus.insertMenu(index, object)
            onObjectRemoved: (index, object) => menus.removeMenu(object)
        }
    }

    ToolButton {
        id: hud
        anchors.right: bar.right
        anchors.verticalCenter: bar.verticalCenter
        visible: bar.hudButton
        checkable: true
        checked: bar.hudShown
        enabled: bar.hudAvailable
        topInset: 0
        bottomInset: 0
        topPadding: Theme.spaceXXS
        bottomPadding: Theme.spaceXXS
        icon.width: bar.hudIconSize
        icon.height: bar.hudIconSize
        implicitHeight: implicitContentHeight + topPadding + bottomPadding
        icon.source: IconSources.Icon("gamepad")
        Accessible.name: qsTr("Show HUD")
        ToolTip.text: qsTr("Show HUD")
        ToolTip.visible: hovered
        ToolTip.delay: Theme.tipDelayMs
        onClicked: bar.hudToggled()
    }
}
