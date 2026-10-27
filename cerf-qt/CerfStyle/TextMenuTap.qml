import QtQuick

TapHandler {
    id: handler
    property Component menu: Component {
        TextEditMenu {}
    }

    acceptedButtons: Qt.RightButton
    enabled: !TextMenuSupport.builtIn

    onTapped: point => {
        const opened = menu.createObject(handler.parent, { editor: handler.parent })
        opened.closed.connect(opened.destroy)
        opened.popup(point.position.x, point.position.y)
    }
}
