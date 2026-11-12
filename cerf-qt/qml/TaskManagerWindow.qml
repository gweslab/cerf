import QtQuick
import QtQuick.Layouts
import CerfStyle
import Cerfman

ApplicationWindow {
    id: root
    property QtObject controller: null
    property var chosenKey: undefined
    readonly property int chosenRow: rowOf(controller.rows, chosenKey)
    readonly property bool selected: chosenRow >= 0
    readonly property var selectedKey: selected ? chosenKey : 0

    function rowOf(rows, key) {
        for (let i = 0; i < rows.length; ++i) {
            if (rows[i].key === key)
                return i
        }
        return -1
    }

    function step(delta) {
        const rows = controller.rows
        if (rows.length === 0)
            return
        const next = chosenRow < 0 ? 0 : Math.max(0, Math.min(rows.length - 1, chosenRow + delta))
        chosenKey = rows[next].key
        rowsView.positionViewAtIndex(next, ListView.Contain)
    }

    title: controller.title
    width: controller.clientWidth
    height: controller.clientHeight
    minimumWidth: controller.minimumClientWidth
    minimumHeight: controller.minimumClientHeight

    Component.onCompleted: WindowLifetime.DeleteWhenClosed(root)


    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.spaceM
        spacing: Theme.spaceM

        TabBar {
            id: tabs
            onCurrentIndexChanged: {
                root.chosenKey = undefined
                root.controller.SetProcesses(currentIndex === 1)
            }

            TabButton {
                text: qsTr("Windows")
                width: implicitWidth
            }
            TabButton {
                text: qsTr("Processes")
                width: implicitWidth
            }
        }

        TableList {
            Layout.fillWidth: true
            Layout.fillHeight: true
            columns: [
                Repeater {
                    model: root.controller.columns
                    ColumnTitle {
                        required property var modelData
                        Layout.preferredWidth: modelData.width
                        text: modelData.title
                    }
                }
            ]

            TableListView {
                id: rowsView
                model: root.controller.rows
                keyNavigationEnabled: false
                Keys.onUpPressed: root.step(-1)
                Keys.onDownPressed: root.step(1)

                delegate: TableRow {
                    id: row
                    required property var modelData
                    width: ListView.view.width
                    highlighted: row.modelData.key === root.chosenKey
                    onClicked: root.chosenKey = row.modelData.key

                    TapHandler {
                        acceptedButtons: Qt.RightButton
                        onTapped: eventPoint => {
                            root.chosenKey = row.modelData.key
                            rowMenu.popup()
                        }
                    }

                    Repeater {
                        model: row.modelData.cells
                        Label {
                            required property string modelData
                            required property int index
                            Layout.preferredWidth: root.controller.columns[index].width
                            text: modelData
                            elide: Text.ElideRight
                        }
                    }
                }
            }
        }

        RowLayout {
            spacing: Theme.spaceM

            Button {
                text: qsTr("Switch to")
                onClicked: root.controller.SwitchTo(root.selected, root.selectedKey)
            }
            Button {
                text: qsTr("Kill")
                onClicked: root.controller.Kill(root.selected, root.selectedKey)
            }
        }

        RowLayout {
            spacing: Theme.spaceM

            Label {
                text: qsTr("Run:")
            }
            TextField {
                id: command
                Layout.fillWidth: true
                maximumLength: root.controller.runLimit
                onAccepted: root.controller.Run(text)
            }
            Button {
                text: qsTr("Run")
                highlighted: true
                onClicked: root.controller.Run(command.text)
            }
            StatusLabel {
                text: root.controller.statusText
                ok: root.controller.statusOk
                failed: root.controller.statusFailed
                elide: Text.ElideRight
                Layout.maximumWidth: command.width
            }
        }
    }

    Menu {
        id: rowMenu
        MenuItem {
            text: qsTr("Switch to")
            onTriggered: root.controller.SwitchTo(root.selected, root.selectedKey)
        }
        MenuItem {
            text: qsTr("Kill")
            onTriggered: root.controller.Kill(root.selected, root.selectedKey)
        }
    }
}
