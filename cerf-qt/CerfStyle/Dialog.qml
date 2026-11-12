import QtQuick
import QtQuick.Controls.Material as M
import QtQuick.Templates as T

M.Dialog {
    id: control
    readonly property int windowWidth: Math.ceil(implicitWidth)
    readonly property int windowHeight: Math.ceil(implicitHeight)

    popupType: Theme.touchPlatform ? T.Popup.Item : T.Popup.Window
    dim: Theme.touchPlatform && modal

    Component.onCompleted: {
        if (!Theme.touchPlatform) {
            enter = null
            exit = null
            background.color = Qt.binding(() => Theme.dark ? Theme.pageBg : control.Material.dialogColor)
        }
    }

    Connections {
        target: control.background.Window
        function onWindowChanged() {
            const window = control.background.Window.window
            if (!window || control.background.parent.parent !== window.contentItem)
                return
            window.color = Qt.binding(() => control.background.color)
            window.minimumWidth = Qt.binding(() => control.windowWidth)
            window.maximumWidth = Qt.binding(() => control.windowWidth)
            window.minimumHeight = Qt.binding(() => control.windowHeight)
            window.maximumHeight = Qt.binding(() => control.windowHeight)
        }
    }

    T.Overlay.modal: Rectangle {
        color: Theme.backdrop
        Behavior on opacity { NumberAnimation { duration: Theme.morphMs } }
    }
    T.Overlay.modeless: Rectangle {
        color: Theme.backdrop
        Behavior on opacity { NumberAnimation { duration: Theme.morphMs } }
    }
}
