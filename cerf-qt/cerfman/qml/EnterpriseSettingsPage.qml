import QtQuick
import QtQuick.Dialogs
import QtQuick.Layouts
import CerfStyle

ScrollPage {
    id: page
    property string splash: EnterpriseModel.Splash()
    property string logoPath: EnterpriseModel.LogoPath()
    readonly property var shutdownRows: Array.from(EnterpriseModel.ShutdownActions())
    property var shutdownChecked: shutdownRows.reduce((checked, row) => {
        checked[row.id] = row.checked
        return checked
    }, {})
    property var saved: ({})

    function values() {
        return {"enabled": enabledRow.checked, "password": passwordField.text, "device": deviceField.text,
                "splash": splash, "logoPath": logoPath, "kiosk": kioskRow.checked,
                "shutdown": shutdownRows.filter(row => shutdownChecked[row.id]).map(row => row.id)}
    }

    function setShutdown(id, checked) {
        if (shutdownChecked[id] === checked)
            return
        const next = Object.assign({}, shutdownChecked)
        next[id] = checked
        shutdownChecked = next
    }

    function accept() {
        const now = values()
        const problem = EnterpriseModel.Problem(now)
        if (problem !== "") {
            Dialogs.inform(page, qsTr("Enterprise"), problem)
            return false
        }
        if (JSON.stringify(now) === JSON.stringify(saved))
            return true
        const error = EnterpriseModel.Save(now)
        if (error !== "") {
            Dialogs.inform(page, qsTr("Enterprise"), qsTr("Could not save:\n%1").arg(error))
            return false
        }
        saved = now
        return true
    }

    Component.onCompleted: saved = values()

    FileDialog {
        id: logoDialog
        title: qsTr("Pick the logo")
        nameFilters: [qsTr("SVG images (*.svg)")]
        onAccepted: {
            const path = FileAccess.LocalPath(selectedFile)
            if (path !== "")
                page.logoPath = FileAccess.PickedValue(path, EnterpriseModel.LogoFolder())
        }
    }

    SettingsGroup {
        SwitchRow {
            id: enabledRow
            title: qsTr("Enabled")
            description: qsTr("The device manager opens only with the password.")
            divider: false
            checked: EnterpriseModel.Enabled()
        }
        SettingsRow {
            title: qsTr("Password")
            description: qsTr("At least %1 characters.").arg(EnterpriseModel.MinPasswordLength())

            TextField {
                id: passwordField
                width: parent.width
                echoMode: TextInput.PasswordEchoOnEdit
                inputMethodHints: Qt.ImhSensitiveData | Qt.ImhNoPredictiveText | Qt.ImhNoAutoUppercase
                text: EnterpriseModel.Password()
            }
        }
        SettingsRow {
            title: qsTr("Device")
            description: qsTr("The device that starts when the command line names none.")

            TextField {
                id: deviceField
                width: parent.width
                text: EnterpriseModel.Device()
            }
        }
        SettingsRow {
            title: qsTr("Splash")

            ChoiceBox {
                values: EnterpriseModel.SplashValues()
                current: page.splash
                labelOf: v => EnterpriseModel.SplashLabel(v)
                onPicked: value => page.splash = value
            }
        }
        SettingsRow {
            title: qsTr("Logo")

            PathField {
                width: parent.width
                value: page.logoPath
                onEdited: text => page.logoPath = text
                onBrowse: {
                    logoDialog.currentFolder = FileAccess.BrowseFolder(page.logoPath, EnterpriseModel.LogoFolder())
                    logoDialog.open()
                }
            }
        }
        SwitchRow {
            id: kioskRow
            title: qsTr("Kiosk mode")
            checked: EnterpriseModel.Kiosk()
        }
    }

    SectionLabel {
        text: qsTr("Shutdown policy")
    }

    SettingsGroup {
        Repeater {
            model: page.shutdownRows

            SwitchRow {
                required property var modelData
                required property int index
                title: modelData.label
                divider: index > 0
                checked: modelData.checked
                onCheckedChanged: page.setShutdown(modelData.id, checked)
            }
        }
    }
}
