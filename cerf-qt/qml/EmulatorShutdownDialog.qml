import QtQuick
import QtQuick.Layouts
import CerfStyle

EmulatorDialog {
    id: dialog
    readonly property bool exiting: actions.currentIndex === texts.exitAction
    readonly property int tickMs: 15
    readonly property bool countsDown: !Theme.touchPlatform && texts.countsDown
    property bool counting: countsDown
    property real countdownStart: 0
    property int remainingMs: texts.countdownMs

    function commit() {
        chosen = {action: actions.currentIndex, save: save.checked, remember: remember.checked}
        close()
    }

    function stopCountdown() {
        counting = false
    }

    title: Theme.touchPlatform ? texts.heading : texts.title
    preferredWidth: 400
    contentHeight: body.implicitHeight

    onOpened: countdownStart = Date.now()

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

    Timer {
        interval: dialog.tickMs
        repeat: true
        running: dialog.counting && dialog.opened
        onTriggered: {
            dialog.remainingMs = Math.max(0, dialog.texts.countdownMs - (Date.now() - dialog.countdownStart))
            if (dialog.remainingMs === 0) {
                dialog.stopCountdown()
                dialog.commit()
            }
        }
    }

    PointHandler {
        parent: dialog.background
        acceptedButtons: Qt.AllButtons
        onActiveChanged: {
            if (active)
                dialog.stopCountdown()
        }
    }

    SymbolFrame {
        id: body
        width: dialog.availableWidth
        asset: Theme.touchPlatform ? "" : "suspend"

        ColumnLayout {
            id: column
            Layout.fillWidth: true
            spacing: Theme.spaceL

            Label {
                Layout.fillWidth: true
                text: dialog.texts.intro
                wrapMode: Text.Wrap
            }
            ComboBox {
                id: actions
                Layout.fillWidth: true
                model: dialog.texts.actions
                onActivated: dialog.stopCountdown()
                onDownChanged: {
                    if (down)
                        dialog.stopCountdown()
                }
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
                        onToggled: dialog.stopCountdown()
                    }
                }
                OptionRow {
                    Layout.fillWidth: true
                    wideControl: false
                    title: dialog.texts.rememberLabel

                    Switch {
                        id: remember
                        onToggled: dialog.stopCountdown()
                    }
                }
            }
            Label {
                Layout.fillWidth: true
                visible: !dialog.exiting
                text: dialog.texts.descriptions[actions.currentIndex]
                wrapMode: Text.Wrap
            }
            ColumnLayout {
                Layout.fillWidth: true
                visible: dialog.countsDown
                opacity: dialog.counting && dialog.exiting ? 1 : 0
                spacing: Theme.spaceXS

                ProgressBar {
                    Layout.fillWidth: true
                    value: dialog.remainingMs / dialog.texts.countdownMs
                }
                Label {
                    Layout.alignment: Qt.AlignHCenter
                    text: qsTr("(%1s left)").arg(Math.ceil(dialog.remainingMs / 1000))
                }
            }
        }
    }
}
