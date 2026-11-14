import QtQuick

WizardPage {
    id: page
    required property string name
    required property QtObject flows
    signal closed()

    function goBack() {
        closed()
        return true
    }

    function start() {
        const reply = DeviceClone.Start(name, options.personal, options.link, options.rom, options.storage,
                                        options.savedState)
        if (!flows.failed(reply, page))
            closed()
    }

    title: qsTr("Clone %1").arg(DeviceActions.DisplayName(name))
    actionName: qsTr("Clone")
    actionEnabled: !ManagerOperations.busy
    onAction: start()
    onBack: closed()
    onCancel: closed()

    ScrollPage {
        anchors.fill: parent

        DeviceCopyOptions {
            id: options
            name: page.name
            cloning: true
        }
    }
}
