import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

EmulatorDialog {
    id: dialog

    function pick(choice) {
        chosen = choice
        close()
    }

    ColumnLayout {
        width: dialog.availableWidth
        spacing: Theme.spaceL

        Repeater {
            model: dialog.texts.paragraphs
            Label {
                required property string modelData
                Layout.fillWidth: true
                text: modelData
                wrapMode: Text.Wrap
            }
        }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.topMargin: Theme.spaceS
            spacing: Theme.spaceS

            Button {
                Layout.fillWidth: true
                text: dialog.texts.switchLabel
                highlighted: true
                onClicked: dialog.pick(dialog.texts.switchChoice)
            }
            Button {
                Layout.fillWidth: true
                text: dialog.texts.changeLabel
                onClicked: dialog.pick(dialog.texts.resolutionChoice)
            }
            Button {
                Layout.fillWidth: true
                text: dialog.texts.closeLabel
                onClicked: dialog.close()
            }
        }
    }
}
