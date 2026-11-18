pragma ComponentBehavior: Bound

import QtQuick
import QtQuick.Layouts
import CerfStyle

PopupDialog {
    id: dialog
    property string name
    property bool bootable: true
    property var states: Array.from(DeviceActions.SavedStates(name))
    readonly property bool narrow: availableWidth < Theme.narrowTableWidth
    readonly property int dateWidth: 120
    readonly property int sizeWidth: 90
    readonly property int actionWidth: 40
    signal picked(var state)
    signal removeRequested(var state)

    function reload() {
        states = Array.from(DeviceActions.SavedStates(name))
        if (states.length === 0)
            close()
    }

    function pick(state) {
        picked(state)
        close()
    }

    title: bootable ? qsTr("Boot a saved state") : qsTr("Delete saved state")
    preferredWidth: 640
    closePolicy: Popup.CloseOnEscape
    contentHeight: body.implicitHeight

    onClosed: destroy()

    rightToLeftButtons: Button {
        text: qsTr("Cancel")
        onClicked: dialog.close()
    }

    ColumnLayout {
        id: body
        width: dialog.availableWidth
        spacing: Theme.spaceM

        Label {
            Layout.fillWidth: true
            text: dialog.bootable ? qsTr("Choose the state to boot.") : qsTr("Choose the state to delete.")
            wrapMode: Text.Wrap
        }

        TableList {
            Layout.fillWidth: true
            headerVisible: !dialog.narrow
            columns: [
                ColumnTitle {
                    Layout.fillWidth: true
                    text: qsTr("State")
                },
                ColumnTitle {
                    Layout.preferredWidth: dialog.dateWidth
                    text: qsTr("Date")
                },
                ColumnTitle {
                    Layout.preferredWidth: dialog.sizeWidth
                    text: qsTr("Size")
                },
                Item {
                    Layout.preferredWidth: dialog.actionWidth
                }
            ]

            Repeater {
                model: dialog.states

                delegate: TableRow {
                    id: row
                    required property var modelData
                    Layout.fillWidth: true
                    hoverEnabled: dialog.bootable
                    onClicked: if (dialog.bootable) dialog.pick(row.modelData)

                    FoldedCell {
                        folded: dialog.narrow
                        text: row.modelData.crash ? qsTr("Crash state") : qsTr("Saved state")
                        caption: row.modelData.details
                    }
                    SecondaryLabel {
                        Layout.preferredWidth: dialog.dateWidth
                        visible: !dialog.narrow
                        text: row.modelData.when
                    }
                    SecondaryLabel {
                        Layout.preferredWidth: dialog.sizeWidth
                        visible: !dialog.narrow
                        text: row.modelData.size
                    }
                    ToolButton {
                        Layout.preferredWidth: dialog.actionWidth
                        icon.source: IconSources.Icon("delete_history")
                        Accessible.name: qsTr("Remove")
                        ToolTip.visible: hovered
                        ToolTip.text: qsTr("Remove")
                        onClicked: dialog.removeRequested(row.modelData)
                    }
                }
            }
        }
    }
}
