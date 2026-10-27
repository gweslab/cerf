import QtQuick
import QtQuick.Controls

PopupDialog {
    id: dialog
    property string message: ""
    property bool rich: false
    property var buttons: [qsTr("OK")]
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
        onActivated: dialog.finish(dialog.buttons[0])
    }

    rightToLeftButtons: Repeater {
        model: dialog.buttons.slice().reverse()

        Button {
            required property string modelData
            required property int index
            text: modelData
            highlighted: index === dialog.buttons.length - 1
            onClicked: dialog.finish(modelData)
        }
    }

    ScrollView {
        anchors.fill: parent
        contentWidth: availableWidth

        MessageText {
            id: body
            width: dialog.availableWidth
            text: dialog.message
            textFormat: dialog.rich ? TextEdit.RichText : TextEdit.PlainText
        }
    }
}
