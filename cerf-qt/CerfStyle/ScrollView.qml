import QtQuick
import QtQuick.Controls.Material as M

M.ScrollView {
    id: control
    property real keyboardRoom: 0
    readonly property real visibleHeight: availableHeight - keyboardRoom
    property real revealedHeight: 0

    M.ScrollBar.vertical.interactive: !Theme.touchPlatform
    M.ScrollBar.horizontal.interactive: !Theme.touchPlatform

    function measureKeyboard() {
        const window = control.Window.window
        if (window === null || !Qt.inputMethod.visible) {
            keyboardRoom = 0
            return
        }
        const top = Math.max(control.mapToItem(null, 0, 0).y, window.height - control.WindowInsets.bottom)
        const bottom = Math.min(control.mapToItem(null, 0, control.height).y, window.height)
        keyboardRoom = Math.max(0, bottom - top)
    }

    function focusedContent() {
        const flick = control.contentItem
        const window = control.Window.window
        if (flick === null || window === null || !Qt.inputMethod.visible)
            return null
        for (let item = window.activeFocusItem; item !== null; item = item.parent) {
            if (item === flick.contentItem)
                return window.activeFocusItem
        }
        return null
    }

    function shown(item, viewHeight) {
        const rect = item.mapToItem(control.contentItem, 0, 0, item.width, item.height)
        return rect.y + rect.height >= 0 && rect.y <= viewHeight
    }

    function scrollEnd() {
        const flick = control.contentItem
        return Math.max(flick.originY, flick.contentHeight + flick.bottomMargin - flick.height + flick.originY)
    }

    function reveal(item) {
        const flick = control.contentItem
        const rect = item.mapToItem(flick, 0, 0, item.width, item.height)
        const viewHeight = visibleHeight
        let delta = 0
        if (rect.y + rect.height > viewHeight && rect.y > 0) {
            delta = rect.height > viewHeight ? rect.y : rect.y + rect.height - viewHeight
            delta = Math.min(delta, scrollEnd() - flick.contentY)
        } else if (rect.y < 0 && rect.y + rect.height < viewHeight) {
            delta = rect.height > viewHeight ? rect.y + rect.height - viewHeight : rect.y
            delta = Math.max(delta, flick.originY - flick.contentY)
        }
        if (delta !== 0)
            flick.contentY += delta
    }

    function revealFocus() {
        const item = focusedContent()
        if (item !== null)
            reveal(item)
    }

    Component.onCompleted: revealedHeight = visibleHeight
    onHeightChanged: Qt.callLater(measureKeyboard)
    onVisibleHeightChanged: {
        const previous = revealedHeight
        revealedHeight = visibleHeight
        const item = focusedContent()
        if (item !== null && shown(item, previous))
            Qt.callLater(revealFocus)
    }

    Connections {
        target: control.WindowInsets
        function onChanged() { Qt.callLater(control.measureKeyboard) }
    }
    Connections {
        target: control.Window.window
        function onActiveFocusItemChanged() { Qt.callLater(control.revealFocus) }
    }
    Binding {
        target: control.contentItem
        property: "bottomMargin"
        value: control.keyboardRoom
    }
}
