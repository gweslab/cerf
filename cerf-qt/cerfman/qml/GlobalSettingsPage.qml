import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

ScrollPage {
    id: page
    property string channel: SettingsModel.UpdateChannel()
    property int scale: SettingsModel.DefaultScale()
    property var saved: ({})

    function snapshot() {
        return {"hostKey": JSON.stringify(capture.vks), "channel": channel, "scale": scale,
                "discord": discord.checked}
    }

    function accept(done) {
        DeviceActions.verboseLogs = verbose.checked
        if (JSON.stringify(snapshot()) === JSON.stringify(saved)) {
            done()
            return
        }
        const error = SettingsModel.Save(capture.vks, channel, scale, discord.checked)
        if (error !== "") {
            Dialogs.inform(page, qsTr("Settings"), qsTr("Could not save:\n%1").arg(error))
            return
        }
        saved = snapshot()
        Dialogs.inform(page, qsTr("Settings saved"), qsTr("Emulator settings take effect only in newly launched instances."), done)
    }

    Component.onCompleted: saved = snapshot()

    SettingsGroup {
        SettingsRow {
            visible: !Theme.touchPlatform
            title: qsTr("Host key")
            description: qsTr("Reassign a key you use to defocus keyboard/mouse from guest")
            divider: false

            RowLayout {
                width: parent.width
                spacing: Theme.spaceS

                Button {
                    Layout.fillWidth: true
                    text: capture.label
                    onClicked: capture.Begin()

                    HostKeyCapture {
                        id: capture
                        anchors.fill: parent
                        vks: SettingsModel.HostKeyVks()
                        resetVks: SettingsModel.ResetHostKeyVks()
                    }
                }
                Button {
                    text: qsTr("Reset")
                    onClicked: capture.Reset()
                }
            }
        }
        SettingsRow {
            title: qsTr("Update channel")
            description: qsTr("Choose which updates %1 offers.").arg(ProductLinks.productName)
            divider: !Theme.touchPlatform

            ColumnLayout {
                width: parent.width
                spacing: Theme.spaceXS

                ChoiceBox {
                    Layout.fillWidth: true
                    values: SettingsModel.ChannelValues()
                    current: page.channel
                    labelOf: v => SettingsModel.ChannelLabel(v)
                    onPicked: value => page.channel = value
                }
                CaptionLabel {
                    Layout.fillWidth: true
                    text: SettingsModel.ChannelHint(page.channel)
                    wrapMode: Text.Wrap
                }
            }
        }
        SettingsRow {
            visible: !Theme.touchPlatform
            title: qsTr("Default scale")

            ChoiceBox {
                values: SettingsModel.ScaleValues()
                current: page.scale
                labelOf: v => SettingsModel.ScaleLabel(v)
                onPicked: value => page.scale = value
            }
        }
        SwitchRow {
            id: discord
            visible: !Theme.touchPlatform
            title: qsTr("Discord Rich Presence")
            description: qsTr("Shows the device and OS version in your Discord profile.")
            checked: SettingsModel.DiscordRichPresence()
        }
        SwitchRow {
            id: verbose
            title: qsTr("Verbose logs")
            description: qsTr("Resets when %1 restarts.").arg(ProductLinks.productName)
            checked: DeviceActions.verboseLogs
        }
    }
}
