import QtQuick
import QtQuick.Controls

StackView {
    id: wizard
    required property QtObject flows
    property bool mobile: false
    property bool closable: false
    readonly property bool atStart: depth <= 1
    signal finished()

    function restart() {
        clear()
        push(chooseStep)
    }

    function goBack() {
        if (atStart)
            return false
        pop()
        return true
    }

    function sourcesApplied() {
        pop()
        BundleCatalog.Refresh(true)
    }

    initialItem: chooseStep

    Component {
        id: chooseStep
        WizardChoose {
            mobile: wizard.mobile
            closable: wizard.closable
            onLocalRom: wizard.push(formStep)
            onDownload: wizard.push(downloadStep)
            onCancel: wizard.finished()
        }
    }

    Component {
        id: formStep
        NewDeviceForm {
            id: form
            flows: wizard.flows
            mobile: wizard.mobile
            onBack: wizard.pop()
            onCancel: wizard.finished()
            onCreated: wizard.finished()
            onPickBoard: current => wizard.push(pickerStep, {"current": current, "form": form})
        }
    }

    Component {
        id: pickerStep
        BoardPickerPage {
            id: picker
            property var form
            mobile: wizard.mobile
            onPicked: boardId => {
                picker.form.setBoard(boardId)
                wizard.pop()
            }
            onBack: wizard.pop()
            onCancel: wizard.finished()
        }
    }

    Component {
        id: downloadStep
        DownloadRomsPage {
            flows: wizard.flows
            mobile: wizard.mobile
            onBack: wizard.pop()
            onCancel: wizard.finished()
            onStarted: wizard.finished()
            onSources: wizard.push(sourcesStep)
        }
    }

    Component {
        id: sourcesStep
        SourcesPage {
            flows: wizard.flows
            mobile: wizard.mobile
            onApplied: wizard.sourcesApplied()
            onBack: wizard.pop()
            onCancel: wizard.finished()
        }
    }
}
