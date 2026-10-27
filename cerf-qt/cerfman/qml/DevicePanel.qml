import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

Item {
    id: panel
    required property QtObject commands
    property var row: null
    property bool busy: false
    property int revision: 0
    readonly property bool running: row !== null && row.state === DeviceCards.runningState
    readonly property bool saved: row !== null && row.saved
    readonly property int heroMaximum: 280
    readonly property int heroMinimum: 56
    readonly property real heroAspect: 3 / 4
    readonly property real heroHeight: Math.min(width * heroAspect, heroMaximum)
    property string shownName: ""
    property bool shownRunning: false
    property int shownRevision: -1
    property QtObject sheet: null
    property var info: DeviceCards.Details("")

    function reload() {
        const name = row !== null ? row.name : ""
        if (name === shownName && running === shownRunning && revision === shownRevision)
            return
        shownName = name
        shownRunning = running
        shownRevision = revision
        sheet = name !== "" ? PropertySheets.CreateForDevice(name, running, "") : null
        info = DeviceCards.Details(name)
    }

    onRowChanged: reload()
    onRevisionChanged: reload()
    Component.onCompleted: reload()

    Flickable {
        id: flick
        anchors.fill: parent
        visible: panel.row !== null
        clip: true
        contentWidth: width
        contentHeight: body.implicitHeight
        boundsBehavior: Flickable.StopAtBounds
        ScrollBar.vertical: scrollBar

        ColumnLayout {
            id: body
            anchors.left: parent.left
            anchors.right: parent.right
            anchors.leftMargin: Theme.spaceXL
            anchors.rightMargin: Theme.spaceXL
            spacing: Theme.spaceXL

            Item {
                Layout.preferredHeight: panel.heroHeight
            }

            Flow {
                Layout.fillWidth: true
                spacing: Theme.spaceXS

                Row {
                    ToolButton {
                        text: panel.row !== null ? panel.row.launchLabel : ""
                        icon.source: IconSources.launchIcon
                        enabled: !panel.busy
                        onClicked: panel.commands.launch(panel.row.name, "")
                    }
                    ToolButton {
                        visible: panel.saved
                        icon.source: IconSources.Icon("arrow_drop_down")
                        enabled: !panel.busy
                        Accessible.name: qsTr("Boot mode")
                        onClicked: bootMenu.popup(this, 0, height)

                        Menu {
                            id: bootMenu
                            MenuItem {
                                text: qsTr("Warm boot")
                                onTriggered: panel.commands.launch(panel.row.name, DeviceActions.warmBoot)
                            }
                            MenuItem {
                                text: qsTr("Cold boot")
                                onTriggered: panel.commands.launch(panel.row.name, DeviceActions.coldBoot)
                            }
                        }
                    }
                }
                ToolButton {
                    visible: panel.row !== null && panel.row.updatable
                    text: qsTr("Update")
                    icon.source: IconSources.Icon("update")
                    enabled: !panel.busy
                    onClicked: panel.commands.updateDevice(panel.row.name)
                }
                ToolButton {
                    text: qsTr("Delete")
                    icon.source: IconSources.Icon("delete")
                    enabled: !panel.busy && panel.row !== null && panel.row.removable
                    onClicked: panel.commands.remove(panel.row.name)
                }
                ToolButton {
                    text: qsTr("Discard State")
                    icon.source: IconSources.Icon("delete_history")
                    enabled: !panel.busy && panel.saved
                    onClicked: panel.commands.discard(panel.row.name)
                }
            }

            DeviceDetails {
                Layout.fillWidth: true
                info: panel.info
                addonsEnabled: !panel.busy && !panel.running
                onPackageAction: pkg => panel.commands.packageAction(panel.row.name, pkg)
            }

            ConfigPreview {
                Layout.fillWidth: true
                Layout.bottomMargin: Theme.spaceXL
                sheet: panel.sheet
                onOpen: page => panel.commands.openProperties(panel.row.name, page)
            }
        }

        StickyPreview {
            y: flick.contentY
            z: 1
            width: flick.width
            row: panel.row
            previewHeight: Math.max(panel.heroMinimum, panel.heroHeight - flick.contentY)
            restHeight: panel.heroHeight
            enabled: !panel.busy
            onClicked: panel.commands.launch(panel.row.name, "")
        }
    }

    ScrollBar {
        id: scrollBar
        visible: flick.visible
        anchors.top: parent.top
        anchors.bottom: parent.bottom
        anchors.right: parent.right
    }
}
