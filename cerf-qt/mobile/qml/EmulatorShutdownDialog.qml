import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

EmulatorDialog {
    id: dialog
    readonly property bool exiting: actions.currentIndex === texts.exitAction

    function commit() {
        chosen = {action: actions.currentIndex, save: save.checked, remember: remember.checked}
        close()
    }

    contentHeight: column.implicitHeight

    rightToLeftButtons: [
        Button {
            text: dialog.texts.okLabel
            highlighted: true
            onClicked: dialog.commit()
        },
        Button {
            text: dialog.texts.cancelLabel
            onClicked: dialog.close()
        }
    ]

    ColumnLayout {
        id: column
        width: dialog.availableWidth
        spacing: Theme.spaceL

        Label {
            Layout.fillWidth: true
            text: dialog.texts.intro
            wrapMode: Text.Wrap
        }
        Label {
            Layout.fillWidth: true
            text: dialog.texts.question
            wrapMode: Text.Wrap
        }
        ComboBox {
            id: actions
            Layout.fillWidth: true
            model: dialog.texts.actions
        }
        ColumnLayout {
            Layout.fillWidth: true
            visible: dialog.exiting
            spacing: column.spacing

            OptionRow {
                Layout.fillWidth: true
                wideControl: false
                title: dialog.texts.saveTitle
                description: dialog.texts.saveDescription

                Switch {
                    id: save
                    checked: dialog.texts.saveDefault
                }
            }
            OptionRow {
                Layout.fillWidth: true
                wideControl: false
                title: dialog.texts.rememberLabel

                Switch {
                    id: remember
                }
            }
        }
        Label {
            Layout.fillWidth: true
            visible: !dialog.exiting
            text: dialog.texts.descriptions[actions.currentIndex]
            wrapMode: Text.Wrap
        }
    }
}
