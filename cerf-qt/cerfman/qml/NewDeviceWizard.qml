pragma ComponentBehavior: Bound
import QtQuick
import CerfStyle

StackView {
    id: wizard
    required property QtObject flows
    required property string start
    property bool mobile: false
    signal closed()

    function goBack() {
        back()
        return true
    }

    function back() {
        if (depth > 1)
            pop()
        else
            closed()
    }

    function sourcesApplied() {
        pop()
        BundleCatalog.Refresh(true)
    }

    initialItem: start === "download" ? downloadStep : formStep

    Component {
        id: formStep
        NewDeviceForm {
            id: form
            flows: wizard.flows
            mobile: wizard.mobile
            footerBack: false
            onBack: wizard.back()
            onCancel: wizard.closed()
            onCreated: wizard.closed()
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
            onCancel: wizard.closed()
        }
    }

    Component {
        id: downloadStep
        DownloadRomsPage {
            flows: wizard.flows
            mobile: wizard.mobile
            footerBack: false
            onBack: wizard.back()
            onCancel: wizard.closed()
            onStarted: wizard.closed()
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
            onCancel: wizard.closed()
        }
    }
}
