import QtQuick
import CerfStyle

Item {
    id: root
    property QtObject model
    property QtObject overlays
    property string uiFamily
    property real pixelScale: 1

    readonly property int regularCardWidth: 320
    readonly property int regularMinHeight: 300
    readonly property int compactMaxWidth: 360
    readonly property int compactMargin: 1
    readonly property int compactGap: 1
    readonly property int compactPadX: 7
    readonly property int compactPadY: 5
    readonly property int compactRadius: 4
    readonly property int compactShadow: 1
    readonly property int regularRadius: 6
    readonly property int regularShadow: 2
    readonly property int morePadY: 3

    readonly property bool compact: width < regularCardWidth + 2 * Theme.spaceXL || height < regularMinHeight
    readonly property int margin: compact ? compactMargin : Theme.spaceXL
    readonly property int cardWidth: Math.min(compact ? compactMaxWidth : regularCardWidth, width - 2 * margin)
    readonly property int padX: compact ? compactPadX : Theme.spaceL
    readonly property int padY: compact ? compactPadY : Theme.spaceL
    readonly property int gap: compact ? compactGap : Theme.spaceM
    readonly property int lineGap: compact ? 0 : Theme.spaceXXS
    readonly property int cardRadius: compact ? compactRadius : regularRadius
    readonly property int cardShadow: compact ? compactShadow : regularShadow
    readonly property int fontSize: compact ? Theme.cardCompactFontSize : Theme.cardFontSize
    readonly property real budget: height / 2 - margin
    property int firstShown: 0

    function relayout() {
        const count = cards.count
        let used = 0
        let shown = 0
        for (let i = count - 1; i >= 0; --i) {
            const card = cards.itemAt(i)
            if (card === null)
                return
            const need = card.implicitHeight + (shown > 0 ? gap : 0)
            if (shown > 0 && used + need > budget)
                break
            used += need
            ++shown
        }
        while (shown > 1 && count - shown > 0 && used + gap + more.implicitHeight > budget) {
            used -= cards.itemAt(count - shown).implicitHeight + gap
            --shown
        }
        firstShown = count - shown
    }

    function report() {
        const placed = []
        for (let i = 0; i < stack.children.length; ++i) {
            const item = stack.children[i]
            if (!item.visible || item.cardId === undefined)
                continue
            placed.push({"cardId": item.cardId, "x": stack.x + item.x, "y": stack.y + item.y,
                         "width": item.width, "height": item.height})
        }
        overlays.PlaceCards(placed)
    }

    onWidthChanged: Qt.callLater(relayout)
    onHeightChanged: Qt.callLater(relayout)

    Column {
        id: stack
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.margins: root.margin
        width: root.cardWidth
        spacing: root.gap

        onPositioningComplete: root.report()
        onXChanged: Qt.callLater(root.report)
        onYChanged: Qt.callLater(root.report)

        Card {
            id: more
            readonly property int cardId: 0
            sheet: root
            visible: root.firstShown > 0
            tone: "more"
            title: qsTr("+%1 more").arg(root.firstShown)
            body: ""
            bold: false
            verticalPad: root.morePadY
        }

        Repeater {
            id: cards
            model: root.model
            onItemAdded: Qt.callLater(root.relayout)
            onItemRemoved: Qt.callLater(root.relayout)
            delegate: Card {
                required property int index
                required property int cardId
                required title
                required body
                required tone
                sheet: root
                visible: index >= root.firstShown
                bold: true
                verticalPad: root.padY
                onImplicitHeightChanged: Qt.callLater(root.relayout)
            }
        }
    }

    component Card: Item {
        id: card
        property Item sheet
        property string tone
        property string title
        property string body
        property bool bold
        property int verticalPad

        readonly property color fill: tone === "error" ? Theme.cardError
                                    : tone === "success" ? Theme.cardSuccess
                                    : tone === "more" ? Theme.cardMore : Theme.cardWarning
        readonly property color rim: tone === "error" ? Theme.cardErrorRim
                                   : tone === "success" ? Theme.cardSuccessRim
                                   : tone === "more" ? Theme.cardMoreRim : Theme.cardWarningRim
        readonly property color ink: tone === "error" ? Theme.cardErrorText
                                   : tone === "success" ? Theme.cardSuccessText
                                   : tone === "more" ? Theme.cardMoreText : Theme.cardWarningText

        width: sheet.cardWidth
        height: implicitHeight
        implicitHeight: 2 * verticalPad + content.implicitHeight

        Rectangle {
            y: card.sheet.cardShadow
            width: parent.width
            height: parent.height
            radius: card.sheet.cardRadius
            color: Theme.cardShadow
        }

        Rectangle {
            anchors.fill: parent
            radius: card.sheet.cardRadius
            color: card.fill
            border.color: card.rim
            border.width: Theme.hairline / card.sheet.pixelScale
        }

        Column {
            id: content
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.top: parent.top
            anchors.leftMargin: card.sheet.padX
            anchors.rightMargin: card.sheet.padX
            anchors.topMargin: card.verticalPad
            spacing: card.sheet.lineGap

            Text {
                width: parent.width
                text: card.title
                textFormat: Text.PlainText
                wrapMode: Text.WordWrap
                font.family: card.sheet.uiFamily
                font.pixelSize: card.sheet.fontSize
                font.bold: card.bold
                color: card.ink
            }

            Text {
                width: parent.width
                visible: card.body !== ""
                text: card.body
                textFormat: Text.PlainText
                wrapMode: Text.WordWrap
                font.family: card.sheet.uiFamily
                font.pixelSize: card.sheet.fontSize
                color: card.ink
            }
        }
    }
}
