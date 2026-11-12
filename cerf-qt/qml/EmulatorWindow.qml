import QtQuick
import CerfStyle
import Cerfman

ScreenWindow {
    id: root
    property alias surface: guestSurface
    property alias controller: controller
    readonly property QtObject widgetBar: root.touch ? stripWidgets : null
    readonly property QtObject statusBar: footerLoader.item
    readonly property QtObject overlayArea: root.touch ? overlayTouch : null
    property var openDialogs: []
    property var menuTree: null
    property bool chromeShown: true
    readonly property bool touch: Theme.touchPlatform
    readonly property int stripSlideMs: 150
    readonly property int stripDismissPull: 24
    readonly property int bubbleSize: 56
    readonly property int bubbleRing: 3
    readonly property int bubbleMs: 600
    readonly property real bubbleStartScale: 0.5
    readonly property real bubbleEndScale: 1.4

    title: ProductLinks.productName

    Component.onCompleted: WindowLifetime.DeleteWhenClosed(root)
    onActiveChanged: {
        if (!root.touch)
            return
        if (active)
            floatingBar.reveal()
        else if (menuTree !== null)
            menuTree.closeTree()
    }
    onChromeHeightChanged: {
        if (!root.touch)
            controller.RefitWindow()
    }

    menuBar: Loader {
        id: menuRow
        active: !root.touch && !NativeMenuBar.active
        visible: active && root.chromeShown
        sourceComponent: HostMenuBar {
            titles: controller.menuTitles
            contentFor: (index, menu) => controller.Menu(index, menu)
            hudButton: true
            hudShown: controller.hudShown
            hudAvailable: controller.hudAvailable
            onPicked: (menu, id) => controller.MenuPicked(menu, id)
            onMenuClosing: controller.MenuClosing()
            onHudToggled: controller.ToggleHud()
        }
    }

    footer: Loader {
        id: footerLoader
        active: !root.touch
        visible: root.chromeShown
        sourceComponent: StatusBarItem {
            id: hostBar
            background: Theme.windowBarBg
            separator: Theme.windowBarLine
            hover: Theme.windowBarHover

            ToolTip {
                visible: hostBar.tip !== ""
                text: hostBar.tip
                delay: Theme.tipDelayMs
                x: hostBar.tipRect.x + (hostBar.tipRect.width - width) / 2
                y: -height - Theme.spaceS
            }
        }
    }

    EmulatorController {
        id: controller
    }

    Instantiator {
        model: ["topPadding", "bottomPadding", "leftPadding", "rightPadding"]
        delegate: Binding {
            required property string modelData
            target: root
            property: modelData
            value: 0
            when: root.touch
        }
    }

    GuestSurface {
        id: guestSurface
        anchors.fill: parent
        barInsets: Qt.size(verticalBar.visible ? verticalBar.width : 0, horizontalBar.visible ? horizontalBar.height : 0)
        fillColor: Theme.screenBg
        safeMargins: root.touch ? SafeArea.margins : undefined
    }

    ScrollBar {
        id: verticalBar
        visible: !root.touch && guestSurface.scroll.vertical
        orientation: Qt.Vertical
        policy: ScrollBar.AlwaysOn
        anchors.top: parent.top
        anchors.right: parent.right
        anchors.bottom: horizontalBar.visible ? horizontalBar.top : parent.bottom
        size: guestSurface.scroll.verticalSize
        position: guestSurface.scroll.verticalPosition
        onPositionChanged: {
            if (pressed)
                guestSurface.scroll.ScrollTo(false, position)
        }
    }

    ScrollBar {
        id: horizontalBar
        visible: !root.touch && guestSurface.scroll.horizontal
        orientation: Qt.Horizontal
        policy: ScrollBar.AlwaysOn
        anchors.left: parent.left
        anchors.right: verticalBar.visible ? verticalBar.left : parent.right
        anchors.bottom: parent.bottom
        size: guestSurface.scroll.horizontalSize
        position: guestSurface.scroll.horizontalPosition
        onPositionChanged: {
            if (pressed)
                guestSurface.scroll.ScrollTo(true, position)
        }
    }

    OverlayTouchArea {
        id: overlayTouch
        anchors.fill: parent
        visible: root.touch
    }

    Rectangle {
        id: strip
        property bool shown: false
        property bool shownByKeyboard: false
        property var buttons: []
        width: root.width
        height: stripRow.height + strip.WindowInsets.bottom
        y: shown ? root.height - height : root.height
        visible: root.touch && y < root.height
        color: Theme.overlayStrip

        onShownChanged: {
            if (!shown)
                return
            buttons = controller.RowButtons(guestSurface.keyboardRequested)
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
                    width: leadingInset + stripWidgets.width + trailingInset
                    height: stripWidgets.height

                    function activate(at, menu) {
                        const x = Math.max(0, Math.min(stripWidgets.width - 1, at.x - leadingInset))
                        stripWidgets.Activate(x, at.y, menu)
                    }

                    StripWidgetBar {
                        id: stripWidgets
                        backdrop: Theme.overlayStrip
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
        target: root.touch ? SystemBars : null
        function onShown() {
            floatingBar.reveal()
        }
    }

    Connections {
        target: Qt.application
        enabled: root.touch
        function onStateChanged() {
            if (Qt.application.state === Qt.ApplicationActive)
                floatingBar.reveal()
        }
    }

    Connections {
        target: guestSurface
        function onThreeFingerTapped() {
            floatingBar.reveal()
        }
        function onKeyboardRequestedChanged() {
            strip.buttons = controller.RowButtons(guestSurface.keyboardRequested)
            if (guestSurface.keyboardRequested) {
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
        id: floatingBar
        z: 1
        visible: root.touch
        enabled: root.touch
        surface: guestSurface
        emulator: controller
        areaWidth: root.width
        areaHeight: root.height
        stripShown: strip.shown
        stripPaged: strip.paged
        stripProgress: strip.pageProgress
        busy: strip.shown || root.menuTree !== null || root.openDialogs.length > 0
        onStripRequested: root.cycleStrip()
        onFaded: {
            if (root.touch && root.active && root.visibility === Window.FullScreen)
                SystemBars.Hide()
        }
    }

    ToolTip {
        id: hint
        property int bottomGap: 0
        x: (root.width - width) / 2
        y: (root.touch ? strip.y : root.contentItem.height) - height - bottomGap
    }

    ToolTip {
        id: anchoredHint
        property rect anchor: Qt.rect(0, 0, 0, 0)
        parent: Overlay.overlay
        x: Math.max(0, Math.min(Overlay.overlay.width - width, anchor.x + (anchor.width - width) / 2))
        y: anchor.y - height - Theme.spaceS
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
            onPicked: id => controller.MenuPicked(null, id)
            onAboutToHide: controller.MenuClosing()
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
        const menu = menuComponent.createObject(Overlay.overlay, {"model": model})
        menu.branchClosed.connect(() => Qt.callLater(root.settleMenu))
        menuTree = menu
        menu.noteOpenerPointer(Overlay.overlay.mapToGlobal(x, y))
        menu.popup(x, y)
    }

    function settleMenu() {
        if (menuTree === null || menuTree.treeVisible())
            return
        menuTree.destroy()
        menuTree = null
    }

    function goBack() {
        floatingBar.reveal()
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

    function showHintAt(text, ms, anchor) {
        anchoredHint.anchor = anchor
        anchoredHint.show(text, ms)
    }

    function createDialog(name, properties) {
        if (menuTree !== null)
            menuTree.closeTree()
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
