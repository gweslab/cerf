import QtQuick
import QtQuick.Controls.Material
import CerfStyle

Item {
    id: card
    property var row
    property bool selected: false
    signal picked()
    signal activated()
    signal contextRequested(Item item, point at)

    HoverHandler {
        id: hover
    }

    TapHandler {
        onTapped: card.picked()
        onDoubleTapped: card.activated()
        onLongPressed: card.contextRequested(card, point.position)
    }

    TapHandler {
        acceptedButtons: Qt.RightButton
        acceptedDevices: PointerDevice.Mouse | PointerDevice.TouchPad | PointerDevice.Stylus
        onTapped: (eventPoint, button) => card.contextRequested(card, eventPoint.position)
    }

    DevicePreview {
        anchors.fill: parent
        radius: Theme.previewRadius
        row: card.row
        onLaunch: card.activated()
    }

    Rectangle {
        anchors.fill: parent
        radius: Theme.previewRadius
        color: Theme.previewClear
        border.width: Theme.focusLine
        border.color: card.selected ? Material.accentColor : hover.hovered ? Theme.previewHover : Theme.previewClear
    }
}
