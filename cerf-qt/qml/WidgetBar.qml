import QtQuick
import CerfStyle

Item {
    id: root

    component ActivityDot: Rectangle {
        property real unit: 1
        property int dotRadius
        property real bottomInset
        anchors.bottom: parent.bottom
        anchors.bottomMargin: unit * bottomInset
        width: unit * (2 * dotRadius + 1)
        height: width
        radius: width / 2
        border.color: Theme.barDotRim
        border.width: unit
    }

    property alias list: widgets
    property bool strip: false
    property real unit: 1
    property color backdrop: Theme.windowBarBg
    property bool chrome: false

    readonly property int boxWidth: 26
    readonly property int boxHeight: 24
    readonly property int dotRadius: 3
    readonly property real rxDotInset: 0.5
    readonly property real txDotInset: 1.5
    readonly property real dotBottomInset: 1.5
    readonly property int glowMs: 300
    readonly property int scrollPerNotch: 2 * boxWidth
    readonly property int notchAngle: 120

    implicitWidth: view.contentWidth
    implicitHeight: boxHeight * unit

    function report() {
        for (let i = 0; i < view.count; ++i) {
            const item = view.itemAtIndex(i)
            if (item !== null)
                widgets.PlaceWidget(i, item.mapToItem(null, 0, 0, item.width, item.height))
        }
    }

    function scroll(delta) {
        view.contentX = Math.max(0, Math.min(view.contentWidth - view.width, view.contentX - delta))
    }

    BarWidgetList {
        id: widgets
        strip: root.strip
    }

    Rectangle {
        anchors.fill: parent
        visible: root.chrome
        color: root.backdrop
    }

    Rectangle {
        width: parent.width
        height: Theme.hairline
        visible: root.chrome
        color: Theme.windowBarLine
    }

    ListView {
        id: view
        anchors.right: parent.right
        width: Math.min(root.width, contentWidth)
        height: parent.height
        orientation: ListView.Horizontal
        interactive: false
        clip: true
        model: widgets.items

        onContentWidthChanged: {
            positionViewAtEnd()
            Qt.callLater(root.report)
        }
        onContentXChanged: Qt.callLater(root.report)
        onCountChanged: Qt.callLater(root.report)

        delegate: Item {
            id: box
            required property int index
            required property string kind
            required property string tooltip
            required property bool usable
            required property real rxCount
            required property real txCount
            required property url source
            required property int percent
            required property bool unplugged
            required property string level
            required property bool failed
            required property bool folderOn

            property bool rxLit: false
            property bool txLit: false

            width: root.boxWidth * root.unit
            height: root.boxHeight * root.unit

            onRxCountChanged: {
                rxLit = true
                rxGlow.restart()
            }
            onTxCountChanged: {
                txLit = true
                txGlow.restart()
            }

            Timer {
                id: rxGlow
                interval: root.glowMs
                onTriggered: box.rxLit = false
            }

            Timer {
                id: txGlow
                interval: root.glowMs
                onTriggered: box.txLit = false
            }

            Rectangle {
                anchors.fill: parent
                anchors.topMargin: Theme.hairline
                visible: root.chrome && hover.hovered
                color: Theme.windowBarHover
            }

            BarWidgetIcon {
                anchors.fill: parent
                unit: root.unit
                kind: box.kind
                source: box.source
                percent: box.percent
                unplugged: box.unplugged
                level: box.level
                failed: box.failed
                folderOn: box.folderOn
            }

            Rectangle {
                anchors.fill: parent
                visible: !box.usable
                color: root.backdrop
                opacity: Theme.barDisabledOpacity
            }

            ActivityDot {
                visible: box.usable && box.rxLit
                anchors.left: parent.left
                anchors.leftMargin: root.unit * root.rxDotInset
                unit: root.unit
                dotRadius: root.dotRadius
                bottomInset: root.dotBottomInset
                color: Theme.barRx
            }

            ActivityDot {
                visible: box.usable && box.txLit
                anchors.right: parent.right
                anchors.rightMargin: root.unit * root.txDotInset
                unit: root.unit
                dotRadius: root.dotRadius
                bottomInset: root.dotBottomInset
                color: Theme.barTx
            }

            HoverHandler {
                id: hover
                enabled: root.chrome
            }

            TapHandler {
                id: tap
                acceptedButtons: Qt.LeftButton | Qt.RightButton
                onTapped: (point, button) => widgets.Activate(box.index, box.mapToItem(null, point.position),
                                                              button === Qt.RightButton)
                onLongPressed: widgets.Activate(box.index, box.mapToItem(null, point.position), true)
            }

            ToolTip {
                visible: root.chrome && hover.hovered && !tap.pressed && box.tooltip !== ""
                text: box.tooltip
                delay: Theme.tipDelayMs
                x: (parent.width - width) / 2
                y: -height - Theme.spaceS
            }
        }
    }

    WheelHandler {
        enabled: root.chrome
        onWheel: event => {
            const pixels = event.pixelDelta.x !== 0 ? event.pixelDelta.x : event.pixelDelta.y
            const angle = event.angleDelta.x !== 0 ? event.angleDelta.x : event.angleDelta.y
            root.scroll(pixels !== 0 ? pixels : angle * root.scrollPerNotch / root.notchAngle)
        }
    }

    Connections {
        target: root.Window.window
        function onWidthChanged() {
            Qt.callLater(root.report)
        }
        function onHeightChanged() {
            Qt.callLater(root.report)
        }
    }
}
