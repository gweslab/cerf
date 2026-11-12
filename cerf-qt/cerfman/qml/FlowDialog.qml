import QtQuick
import CerfStyle

PopupDialog {
    id: dialog
    property string message: ""
    property string level: ""
    property bool rich: false
    property var buttons: [qsTr("OK")]
    property string enterChoice: buttons[0]
    property string defaultChoice: buttons[buttons.length - 1]
    property string chosen: ""
    signal choice(string text)

    function finish(text) {
        chosen = text
        close()
    }

    closePolicy: Popup.CloseOnEscape
    contentHeight: body.implicitHeight

    onClosed: {
        choice(chosen !== "" ? chosen : defaultChoice)
        destroy()
    }

    DialogEnterShortcut {
        popup: dialog
        onActivated: dialog.finish(dialog.enterChoice)
    }

    rightToLeftButtons: Repeater {
        model: dialog.buttons.slice().reverse()

        Button {
            required property string modelData
            text: modelData
            highlighted: modelData === dialog.enterChoice
            onClicked: dialog.finish(modelData)
        }
    }

    ScrollView {
        anchors.fill: parent
        contentWidth: availableWidth

        SymbolMessage {
            id: body
            width: dialog.availableWidth
            text: dialog.message
            level: dialog.level
            textFormat: dialog.rich ? TextEdit.RichText : TextEdit.PlainText
        }
    }
}
