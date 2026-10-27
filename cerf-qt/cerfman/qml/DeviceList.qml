import QtQuick
import QtQuick.Controls
import CerfStyle

GridView {
    id: list
    property string selectedName
    property real trailingInset: 0
    readonly property int columns: Math.max(1, Math.floor(width / Theme.deviceCardMinWidth))
    signal picked(string name)
    signal activated(string name)
    signal contextRequested(string name, Item item, point at)

    clip: true
    boundsBehavior: Flickable.StopAtBounds
    ScrollBar.vertical: ScrollBar {}
    cellWidth: Math.floor(width / columns)
    cellHeight: Theme.deviceCellHeight
    topMargin: Theme.spaceS
    bottomMargin: Theme.spaceS

    footer: Item {
        height: list.trailingInset
    }

    delegate: Item {
        id: slot
        required property var model
        width: list.cellWidth
        height: list.cellHeight

        DeviceCard {
            anchors.fill: parent
            anchors.margins: Theme.spaceS
            row: slot.model
            selected: slot.model.name === list.selectedName
            onPicked: list.picked(slot.model.name)
            onActivated: list.activated(slot.model.name)
            onContextRequested: (item, at) => list.contextRequested(slot.model.name, item, at)
        }
    }
}
