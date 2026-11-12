import QtQuick
import QtQuick.Controls.Material as M
import QtQuick.Templates as T

M.Menu {
    id: control

    property point openerPointer
    property bool openerPointerKnown: false
    property point pointerAtOpen
    property bool pointerMoved: true

    popupType: Theme.touchPlatform ? T.Popup.Item : T.Popup.Window
    delegate: MenuItem {}
    leftMargin: WindowInsets.leftMargin
    topMargin: WindowInsets.topMargin
    rightMargin: WindowInsets.rightMargin
    bottomMargin: WindowInsets.bottomMargin

    function noteOpenerPointer(globalPoint) {
        openerPointer = globalPoint
        openerPointerKnown = true
    }

    function forgetOpenerPointer() {
        openerPointerKnown = false
    }

    function notePointer(globalPoint) {
        if (pointerMoved)
            return
        pointerMoved = Math.abs(globalPoint.x - pointerAtOpen.x) + Math.abs(globalPoint.y - pointerAtOpen.y)
                > Application.styleHints.startDragDistance
    }

    onAboutToShow: {
        pointerAtOpen = openerPointer
        pointerMoved = !openerPointerKnown
        if (!Theme.touchPlatform)
            MenuDrag.Track(contentItem.Window.window)
    }

    Component.onCompleted: {
        if (!Theme.touchPlatform) {
            background.border.width = Theme.hairline
            background.border.color = Qt.binding(() => Theme.windowBarLine)
        }
        if (Qt.platform.pluginName.startsWith("wayland"))
            exit = null
    }

    contentWidth: {
        let widest = 0
        for (let i = 0; i < count; ++i)
            widest = Math.max(widest, itemAt(i).implicitWidth)
        return Math.ceil(widest)
    }
}
