import QtQuick
import QtQuick.Controls
import QtQuick.Dialogs
import QtQuick.Layouts
import CerfStyle

SheetGroup {
    id: group
    property bool on: false
    property string path: ""
    property string mountName: ""

    function push() {
        const trimmed = path.trim()
        if (on && trimmed !== "")
            sheet.SetValue(SheetIds.shareFolder, trimmed)
        else
            sheet.ClearValue(SheetIds.shareFolder)
        sheet.SetMountPoint(mountName.trim())
    }

    function pick() {
        if (path.trim() !== "")
            folderDialog.currentFolder = FileAccess.FileUrl(path, "")
        folderDialog.open()
    }

    Component.onCompleted: {
        path = sheet.shareFolder
        on = path !== ""
        mountName = sheet.mountPoint
    }

    FolderDialog {
        id: folderDialog
        title: qsTr("Choose a host folder to share with the guest")
        onAccepted: {
            const picked = FileAccess.LocalPath(selectedFolder)
            if (picked === "")
                return
            group.path = picked
            group.on = true
            group.push()
        }
        onRejected: {
            if (group.path.trim() === "") {
                group.on = false
                group.push()
            }
        }
    }

    SwitchRow {
        title: qsTr("Share folder")
        description: qsTr("Mount a host folder as a guest file system.")
        divider: false
        editable: group.editable
        checked: group.on
        onToggled: {
            group.on = checked
            if (checked && group.path.trim() === "")
                group.pick()
            group.push()
        }
    }
    GridLayout {
        id: grid
        Layout.fillWidth: true
        Layout.margins: Theme.spaceXL
        columns: Theme.rowColumns(width, 3)
        columnSpacing: Theme.spaceS
        rowSpacing: Theme.spaceS

        PathField {
            value: group.path
            editable: group.editable
            onEdited: text => {
                group.path = text
                if (text.trim() === "" && group.on)
                    group.on = false
                group.push()
            }
            onBrowse: group.pick()
        }
        SymbolIcon {
            Layout.alignment: Qt.AlignCenter
            name: "arrow_forward"
            rotation: grid.columns === 1 ? 90 : 0
        }
        RowLayout {
            Layout.fillWidth: grid.columns === 1
            Layout.preferredWidth: Theme.optionControlWidth
            spacing: Theme.spaceS
            TextField {
                id: mountField
                Layout.fillWidth: true
                enabled: group.editable
                text: PropertyOptions.MountPointPath(group.mountName)
                onTextEdited: {
                    const typed = text
                    const cursor = cursorPosition
                    const name = PropertyOptions.MountPointName(typed)
                    if (PropertyOptions.MountPointValid(name)) {
                        group.mountName = name
                        group.push()
                    }
                    text = Qt.binding(() => PropertyOptions.MountPointPath(group.mountName))
                    cursorPosition = Math.max(PropertyOptions.MountPointPath("").length,
                                              Math.min(text.length, cursor - (typed.length - text.length)))
                }
            }
            Button {
                enabled: group.editable
                text: qsTr("Reset")
                onClicked: {
                    group.mountName = group.sheet.mountPointDefault
                    group.push()
                }
            }
        }
    }
}
