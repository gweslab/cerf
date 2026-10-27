import QtQuick
import QtQuick.Controls
import CerfStyle
import Cerfman

ApplicationWindow {
    id: root
    property alias surface: guestSurface
    property alias controller: controller
    property alias widgetBar: widgetBar
    property var openDialogs: []
    property var menuTree: null
    readonly property int stripSlideMs: 150
    readonly property int stripDismissPull: 24
    readonly property int bubbleSize: 56
    readonly property int bubbleRing: 3
    readonly property int bubbleMs: 600
    readonly property real bubbleStartScale: 0.5
    readonly property real bubbleEndScale: 1.4

    color: Theme.screenBg
    title: ProductLinks.productName
    topPadding: 0
    bottomPadding: 0
    leftPadding: 0
    rightPadding: 0

    Component.onCompleted: WindowLifetime.DeleteWhenClosed(root)

    EmulatorController {
        id: controller
    }

    GuestSurface {
        id: guestSurface
        anchors.fill: parent
        fillColor: Theme.screenBg
        safeMargins: SafeArea.margins
    }

    Rectangle {
        id: strip
        property bool shown: false
        property bool shownByKeyboard: false
        property var buttons: []
        width: root.width
        height: stripRow.height + strip.WindowInsets.bottom
        y: shown ? root.height - height : root.height
        visible: y < root.height
        color: Theme.overlayStrip

        onShownChanged: {
            if (!shown)
                return
            buttons = controller.RowButtons()
            stripScroll.stop()
            stripFlick.contentX = 0
        }

        Behavior on y {
            NumberAnimation {
                duration: root.stripSlideMs
            }
        }

        DragHandler {
            property real pulled: 0
            target: null
            xAxis.enabled: false
            onActiveTranslationChanged: pulled = activeTranslation.y
            onActiveChanged: {
                if (!active && pulled > root.stripDismissPull)
                    strip.shown = false
                pulled = 0
            }
        }

        readonly property real widgetsPage: Math.min(widgetArea.x, Math.max(0, stripFlick.contentWidth - stripFlick.width))
        readonly property bool paged: widgetsPage > 0
        readonly property real pageProgress: paged ? Math.max(0, Math.min(1, stripFlick.contentX / widgetsPage)) : 0

        NumberAnimation {
            id: stripScroll
            target: stripFlick
            property: "contentX"
            duration: root.stripSlideMs
        }

        Flickable {
            id: stripFlick
            width: strip.width
            height: stripRow.height
            contentWidth: stripRow.width
            contentHeight: height
            flickableDirection: Flickable.HorizontalFlick
            boundsBehavior: Flickable.StopAtBounds
            clip: true

            Row {
                id: stripRow
                spacing: 0
                topPadding: Theme.spaceM
                bottomPadding: Theme.spaceM

                Repeater {
                    model: strip.buttons
                    delegate: SpecialKeyButton {
                        required property var modelData
                        required property int index
                        anchors.verticalCenter: parent.verticalCenter
                        leadingInset: index === 0 ? guestSurface.safeMargins.left : 0
                        label: modelData.label
                        symbol: modelData.symbol
                        held: modelData.held
                        groupStart: modelData.groupStart
                        holdMs: controller.rowHoldMs
                        Accessible.name: modelData.label
                        onKeyDown: controller.PressRowButton(modelData.index)
                        onKeyUp: {
                            controller.ReleaseRowButton(modelData.index)
                            held = false
                        }
                        onKeyCanceled: controller.CancelRowButton(modelData.index)
                        onHeldLong: held = controller.HoldRowButton(modelData.index)
                    }
                }
                Item {
                    id: widgetArea
                    readonly property real leadingInset: strip.buttons.length === 0 ? guestSurface.safeMargins.left : 0
                    readonly property real trailingInset: guestSurface.safeMargins.right
                    anchors.verticalCenter: parent.verticalCenter
                    width: leadingInset + widgetBar.width + trailingInset
                    height: widgetBar.height

                    function activate(at, menu) {
                        const x = Math.max(0, Math.min(widgetBar.width - 1, at.x - leadingInset))
                        widgetBar.Activate(x, at.y, menu)
                    }

                    MobileWidgetBar {
                        id: widgetBar
                        x: widgetArea.leadingInset
                        width: implicitWidth
                        height: implicitHeight
                    }
                    TapHandler {
                        onTapped: eventPoint => widgetArea.activate(eventPoint.position, false)
                        onLongPressed: widgetArea.activate(point.position, true)
                    }
                }
            }
        }
    }

    Connections {
        target: guestSurface
        function onKeyboardRequestedChanged() {
            if (guestSurface.keyboardRequested) {
                strip.buttons = controller.RowButtons()
                if (!strip.shown) {
                    strip.shownByKeyboard = true
                    strip.shown = true
                }
            } else if (strip.shownByKeyboard) {
                strip.shownByKeyboard = false
                strip.shown = false
            }
        }
    }

    FloatingBar {
        z: 1
        surface: guestSurface
        emulator: controller
        areaWidth: root.width
        areaHeight: root.height
        stripShown: strip.shown
        stripPaged: strip.paged
        stripProgress: strip.pageProgress
        onStripRequested: root.cycleStrip()
    }

    ToolTip {
        id: hint
        property int bottomGap: 0
        x: (root.width - width) / 2
        y: strip.y - height - bottomGap
    }

    Component {
        id: tapBubble
        Rectangle {
            id: bubble
            property real cx: 0
            property real cy: 0
            width: root.bubbleSize
            height: root.bubbleSize
            radius: width / 2
            x: cx - width / 2
            y: cy - height / 2
            color: Theme.tapBubble
            border.color: Theme.tapBubbleRing
            border.width: root.bubbleRing
            ParallelAnimation {
                running: true
                NumberAnimation { target: bubble; property: "opacity"; from: 1; to: 0; duration: root.bubbleMs }
                NumberAnimation { target: bubble; property: "scale"; from: root.bubbleStartScale; to: root.bubbleEndScale; duration: root.bubbleMs }
                onFinished: bubble.destroy()
            }
        }
    }

    Component {
        id: menuComponent
        EmulatorMenu {
            onPicked: id => controller.MenuPicked(id)
        }
    }

    Component {
        id: externalDisplayComponent
        ExternalDisplayBox {
            area: Qt.rect(guestSurface.safeMargins.left, guestSurface.safeMargins.top,
                          root.width - guestSurface.safeMargins.left - guestSurface.safeMargins.right,
                          root.height - guestSurface.safeMargins.top - guestSurface.safeMargins.bottom)
            bottomLimit: strip.visible ? strip.y : root.height
        }
    }

    function cycleStrip() {
        if (!strip.shown) {
            strip.shown = true
            return
        }
        if (strip.paged && stripFlick.contentX < strip.widgetsPage - 1) {
            stripScroll.stop()
            stripScroll.from = stripFlick.contentX
            stripScroll.to = strip.widgetsPage
            stripScroll.start()
            return
        }
        strip.shownByKeyboard = false
        strip.shown = false
    }

    function showMenu(model, x, y) {
        if (menuTree !== null)
            menuTree.destroy()
        const menu = menuComponent.createObject(root.contentItem, {"model": model})
        menu.branchClosed.connect(() => Qt.callLater(root.settleMenu))
        menuTree = menu
        menu.popup(x, y)
    }

    function settleMenu() {
        if (menuTree === null || menuTree.treeVisible())
            return
        menuTree.destroy()
        menuTree = null
    }

    function goBack() {
        if (openDialogs.length > 0) {
            openDialogs[openDialogs.length - 1].close()
            return true
        }
        if (menuTree !== null && menuTree.treeVisible())
            menuTree.closeTree()
        else
            controller.RequestClose()
        return true
    }

    function createExternalDisplay() {
        return externalDisplayComponent.createObject(root.contentItem)
    }

    function showTapBubble(x, y) {
        tapBubble.createObject(root.contentItem, {"cx": x, "cy": y})
    }

    function showHint(text, ms, gap) {
        hint.bottomGap = gap
        hint.show(text, ms)
    }

    function createDialog(name, properties) {
        const dialog = Qt.createComponent(name + ".qml").createObject(root.contentItem, properties)
        openDialogs = openDialogs.concat([dialog])
        const ended = dialog.closed !== undefined ? dialog.closed : dialog.finished
        ended.connect(() => { openDialogs = openDialogs.filter(d => d !== dialog) })
        return dialog
    }

    function closeDialogs() {
        for (const dialog of openDialogs.slice()) dialog.close()
    }
}
