import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

OkCancelDialog {
    id: dialog
    property var choices: []
    property string choice
    property bool confirmed: false
    signal chosen(string choice)

    title: qsTr("Reset device")
    preferredWidth: 420

    onOk: {
        confirmed = true
        close()
    }
    onClosed: {
        if (confirmed)
            chosen(choice)
        destroy()
    }

    ColumnLayout {
        width: dialog.availableWidth
        spacing: Theme.spaceS

        Label {
            Layout.fillWidth: true
            text: qsTr("Some properties you changed require a soft reset to take effect. Would you like "
                       + "to perform it?")
            wrapMode: Text.Wrap
        }
        Repeater {
            model: dialog.choices
            delegate: RadioButton {
                required property var modelData
                text: modelData.label
                checked: dialog.choice === modelData.value
                onToggled: if (checked) dialog.choice = modelData.value
            }
        }
    }
}
