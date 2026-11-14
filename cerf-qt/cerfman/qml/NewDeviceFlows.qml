pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Dialogs
import QtQuick.Layouts
import CerfStyle

Item {
    id: creation
    required property QtObject flows
    required property var commands
    readonly property var choices: [
        {"step": "form", "symbol": "folder_open", "title": qsTr("New device from local files")},
        {"step": "download", "symbol": "download", "title": qsTr("Download from bundle repository")},
        {"step": "import", "symbol": "upload", "title": qsTr("Import device")}
    ]

    function open(anchor) {
        if (ManagerOperations.RefuseWhileBusy())
            return
        if (commands.mobile)
            sheet.open()
        else if (anchor)
            menu.popup(anchor, 0, anchor.height)
        else
            menu.popup()
    }

    function start(step) {
        if (step === "import") {
            importDialog.open()
            return
        }
        if (step === "download" && BundleCatalog.RefuseWhileLoading())
            return
        const props = {"flows": flows, "start": step}
        if (commands.touchPlatform)
            commands.pushPage(wizardPage, props)
        else
            wizardWindow.createObject(commands, Object.assign({"transientParent": commands}, props)).show()
    }

    Menu {
        id: menu

        Instantiator {
            model: creation.choices
            delegate: MenuItem {
                required property var modelData
                text: modelData.title
                icon.source: IconSources.Icon(modelData.symbol)
                onTriggered: creation.start(modelData.step)
            }
            onObjectAdded: (index, object) => menu.insertItem(index, object)
            onObjectRemoved: (index, object) => menu.removeItem(object)
        }
    }

    Drawer {
        id: sheet
        parent: Overlay.overlay
        width: parent.width
        edge: Qt.BottomEdge
        dragMargin: 0
        topPadding: Theme.spaceM
        bottomPadding: Theme.spaceM + WindowInsets.bottom

        ColumnLayout {
            width: parent.width
            spacing: 0

            Repeater {
                model: creation.choices
                delegate: ItemDelegate {
                    required property var modelData
                    Layout.fillWidth: true
                    text: modelData.title
                    icon.source: IconSources.Icon(modelData.symbol)
                    onClicked: {
                        sheet.close()
                        creation.start(modelData.step)
                    }
                }
            }
        }
    }

    FileDialog {
        id: importDialog
        title: qsTr("Import a device")
        nameFilters: [qsTr("Zip archives (*.zip)")]
        onAccepted: DeviceImport.Start(selectedFile)
    }

    Component {
        id: wizardWindow
        NewDeviceWindow {}
    }

    Component {
        id: wizardPage
        NewDeviceWizard {
            mobile: true
        }
    }
}
