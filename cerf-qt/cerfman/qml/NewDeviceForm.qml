import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

WizardPage {
    id: form
    required property QtObject flows
    signal pickBoard(string current)
    signal created()

    function setBoard(id) {
        fields.setBoard(id)
    }

    function create() {
        const name = fields.name.trim()
        let reason = UserDeviceCreator.NameProblem(name)
        if (reason === "")
            reason = fields.problem()
        if (reason !== "") {
            flows.inform(qsTr("Cannot create device"), reason, form)
            return
        }
        UserDeviceCreator.Start(name, fields.boardId, fields.currentFiles(), copySwitch.checked)
        created()
    }

    title: qsTr("New device")
    actionName: qsTr("Create")
    actionEnabled: fields.boardId !== "" && fields.name.trim() !== "" && !ManagerOperations.busy
    onAction: form.create()
    Component.onCompleted: fields.setBoard(BoardCatalog.FirstRunningBoard())

    ScrollPage {
        anchors.fill: parent

        BoardRomFields {
            id: fields
            Layout.fillWidth: true
            nameFollowsBoard: true
            onPickBoard: form.pickBoard(fields.boardId)
        }

        SettingsGroup {
            SwitchRow {
                id: copySwitch
                title: qsTr("Copy files to device directory")
                divider: false
                checked: true
            }
        }
    }
}
