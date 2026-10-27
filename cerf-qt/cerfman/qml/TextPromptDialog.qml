import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

OkCancelDialog {
    id: dialog
    property string prompt: ""
    property string value: ""
    property int hints: Qt.ImhNone
    property bool confirmed: false
    signal done(string text)

    onOpened: field.forceActiveFocus()
    onOk: confirm()
    onClosed: {
        if (confirmed)
            done(field.text.trim())
        destroy()
    }

    function confirm() {
        confirmed = true
        close()
    }

    ColumnLayout {
        width: dialog.availableWidth
        spacing: Theme.spaceM

        Label {
            Layout.fillWidth: true
            text: dialog.prompt
            wrapMode: Text.Wrap
        }
        TextField {
            id: field
            Layout.fillWidth: true
            text: dialog.value
            inputMethodHints: dialog.hints
            onAccepted: dialog.confirm()
        }
    }
}
