import QtQuick

WizardPage {
    id: page
    required property string name
    required property string destination
    required property QtObject flows
    property bool started: false
    signal closed()

    function goBack() {
        closed()
        return true
    }

    function replaceDestination(next) {
        DeviceExport.Discard(destination)
        destination = next
    }

    function start() {
        const reply = DeviceExport.Start(name, destination, options.personal, options.link, options.rom,
                                         options.storage, options.savedState)
        if (flows.failed(reply, page))
            return
        started = true
        closed()
    }

    title: qsTr("Export %1").arg(DeviceActions.DisplayName(name))
    actionName: qsTr("Export")
    actionEnabled: destination !== "" && !ManagerOperations.busy
    onAction: start()
    onBack: closed()
    onCancel: closed()
    Component.onDestruction: if (!started) DeviceExport.Discard(destination)

    ScrollPage {
        anchors.fill: parent

        SettingsGroup {
            SettingsRow {
                title: qsTr("Save to")
                divider: false
                PathField {
                    width: parent.width
                    value: page.destination
                    onEdited: text => page.replaceDestination(text)
                    onBrowse: targetDialog.open()
                }
            }
        }
        DeviceCopyOptions {
            id: options
            name: page.name
        }
    }

    ExportTargetDialog {
        id: targetDialog
        name: page.name
        onAccepted: {
            const picked = FileAccess.LocalPath(selectedFile)
            if (picked !== "" && picked !== page.destination)
                page.replaceDestination(picked)
        }
    }
}
