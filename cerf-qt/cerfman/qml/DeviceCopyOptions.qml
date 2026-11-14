import QtQuick

SettingsGroup {
    id: options
    required property string name
    property bool cloning: false
    readonly property var choices: DeviceReplica.Choices(name)
    readonly property alias personal: personalSwitch.checked
    readonly property alias link: linkSwitch.checked
    readonly property alias rom: romSwitch.checked
    readonly property alias storage: storageSwitch.checked
    readonly property alias savedState: stateSwitch.checked
    readonly property bool linkForcesFiles: cloning && linkSwitch.checked
    property bool romChoice: !cloning
    property bool storageChoice: !cloning

    function copied(available, choice) {
        return available && (linkForcesFiles || choice)
    }

    SwitchRow {
        id: personalSwitch
        title: qsTr("Store your personal configuration")
        description: qsTr("All your flags in device properties will be stored.")
        divider: false
        checked: options.cloning
    }
    SwitchRow {
        id: linkSwitch
        title: qsTr("Store ROM bundle repository configuration")
        description: options.cloning ? "" : qsTr("The imported device keeps getting ROM updates.")
        editable: options.choices.link
        checked: options.cloning && options.choices.link
    }
    SwitchRow {
        id: romSwitch
        title: options.cloning ? qsTr("Clone ROM files") : qsTr("Store ROM files")
        description: !options.choices.rom ? qsTr("This device has no ROM files.")
                     : options.cloning
                     ? qsTr("Duplicates %1 of device boot files. Toggle off to use the same files for both devices.")
                           .arg(options.choices.romSize)
                     : qsTr("Adds %1 of device boot files.").arg(options.choices.romSize)
        editable: options.choices.rom && !options.linkForcesFiles
        checked: options.copied(options.choices.rom, options.romChoice)
        onToggled: {
            options.romChoice = checked
            checked = Qt.binding(() => options.copied(options.choices.rom, options.romChoice))
        }
    }
    SwitchRow {
        id: storageSwitch
        title: options.cloning ? qsTr("Clone storage files") : qsTr("Store storage files")
        description: !options.choices.storage ? qsTr("This device has no storage files.")
                     : options.cloning
                     ? qsTr("Duplicates %1 of device storage files. Toggle off to use the same files for both devices.")
                           .arg(options.choices.storageSize)
                     : qsTr("Adds %1 of device storage files. Some devices cannot boot from blank storage.")
                           .arg(options.choices.storageSize)
        editable: options.choices.storage && !options.linkForcesFiles
        checked: options.copied(options.choices.storage, options.storageChoice)
        onToggled: {
            options.storageChoice = checked
            checked = Qt.binding(() => options.copied(options.choices.storage, options.storageChoice))
        }
    }
    SwitchRow {
        id: stateSwitch
        title: options.cloning ? qsTr("Clone saved state") : qsTr("Store saved state")
        description: !options.choices.state ? qsTr("This device has no saved state.")
                     : options.cloning ? qsTr("Duplicates %1 of saved state.").arg(options.choices.stateSize)
                     : qsTr("Adds %1 of saved state.").arg(options.choices.stateSize)
        editable: options.choices.state
    }
}
