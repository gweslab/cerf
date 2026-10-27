import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

Item {
    id: screen
    required property QtObject commands
    property alias model: list.model
    property alias listBottomInset: list.trailingInset
    property string selectedName
    property var selectedRow: null
    property bool compact: false
    property int installed: -1
    property bool busy: false
    property int revision: 0
    property int bundleUpdates: 0
    property string cerfStatus: ""
    property bool cerfAvailable: false
    readonly property string query: tools.query
    readonly property int panelWidth: 400

    Action {
        id: newDeviceAction
        text: qsTr("New")
        icon.source: IconSources.newIcon
        enabled: !screen.busy
        onTriggered: screen.commands.newDevice()
    }

    RowLayout {
        anchors.fill: parent
        spacing: 0

        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            spacing: 0

            DesktopToolBar {
                id: tools
                Layout.fillWidth: true
                visible: !screen.compact
                newAction: newDeviceAction
                onSettings: screen.commands.openSettings()
            }
            Divider {
                Layout.fillWidth: true
                visible: tools.visible
            }
            DeviceList {
                id: list
                Layout.fillWidth: true
                Layout.fillHeight: true
                visible: screen.installed !== 0
                selectedName: screen.selectedName
                onPicked: name => screen.commands.pick(name)
                onActivated: name => screen.commands.launch(name, "")
                onContextRequested: (name, item, at) => screen.commands.contextMenu(name, item, at)
            }
            Item {
                Layout.fillWidth: true
                Layout.fillHeight: true
                visible: screen.installed === 0

                ColumnLayout {
                    anchors.centerIn: parent
                    spacing: Theme.spaceXXL

                    TitleLabel {
                        Layout.alignment: Qt.AlignHCenter
                        level: TitleLabel.Headline
                        text: qsTr("No devices yet")
                    }
                    Button {
                        Layout.alignment: Qt.AlignHCenter
                        action: newDeviceAction
                        highlighted: true
                    }
                }
            }
            DesktopNotifications {
                Layout.fillWidth: true
                visible: !screen.compact && active
                bundleUpdates: screen.bundleUpdates
                cerfStatus: screen.cerfStatus
                cerfAvailable: screen.cerfAvailable
                onUpdateBundles: screen.commands.updateAll()
                onOpenCerfUpdate: screen.commands.offerUpgrade()
            }
        }

        Divider {
            Layout.fillHeight: true
            vertical: true
            visible: panel.visible
        }

        DevicePanel {
            id: panel
            visible: !screen.compact && screen.installed !== 0
            Layout.preferredWidth: screen.panelWidth
            Layout.fillHeight: true
            commands: screen.commands
            row: screen.selectedRow
            busy: screen.busy
            revision: screen.revision
        }
    }
}
