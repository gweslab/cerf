pragma ComponentBehavior: Bound
import QtQuick

Item {
    id: transfer
    required property QtObject flows
    required property var commands

    function refused(name) {
        return ManagerOperations.RefuseWhileBusy() || flows.failed(DeviceActions.RefuseRunning(name))
    }

    function openPage(component, props) {
        if (commands.touchPlatform)
            commands.pushPage(component, props)
        else
            pageWindow.createObject(commands, {"transientParent": commands, "page": component, "properties": props})
                .show()
    }

    function cloneDevice(name) {
        if (!refused(name))
            openPage(clonePage, {"name": name, "flows": flows})
    }

    function exportDevice(name) {
        if (!refused(name))
            targetDialog.createObject(transfer, {"name": name}).open()
    }

    function addRepository(url) {
        if (!flows.failed(SourceRepositories.Add(url)))
            BundleCatalog.Refresh(true)
    }

    Connections {
        target: DeviceClone
        function onCloned(name) {
            transfer.commands.selectDevice(name)
        }
    }

    Connections {
        target: DeviceImport
        function onImported(name, missingRepository) {
            transfer.commands.selectDevice(name)
            if (missingRepository !== "")
                transfer.flows.ask(qsTr("Bundle repository"),
                                   qsTr("Do you want to add this bundle repository?\n\n%1").arg(missingRepository),
                                   () => transfer.addRepository(missingRepository))
        }
    }

    Component {
        id: targetDialog
        ExportTargetDialog {
            id: dialog
            onAccepted: {
                const picked = FileAccess.LocalPath(selectedFile)
                if (picked !== "")
                    transfer.openPage(exportPage, {"name": dialog.name, "destination": picked, "flows": transfer.flows})
                destroy()
            }
            onRejected: destroy()
        }
    }

    Component {
        id: pageWindow
        DevicePageWindow {}
    }

    Component {
        id: exportPage
        ExportDevicePage {
            mobile: transfer.commands.touchPlatform
        }
    }

    Component {
        id: clonePage
        CloneDevicePage {
            mobile: transfer.commands.touchPlatform
        }
    }
}
