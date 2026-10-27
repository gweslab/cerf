import QtQuick
import QtQuick.Controls
import QtQuick.Dialogs
import QtQuick.Layouts
import CerfStyle

ColumnLayout {
    id: fields
    property string boardId: ""
    property alias name: nameField.text
    property var files: emptyFiles()
    property string baseDir: ""
    property bool nameFollowsBoard: false
    property bool editable: true
    property string prefilled: ""
    readonly property var fileRows: DeviceFormRules.FileTypes(boardId)
    signal pickBoard()
    signal changed()

    function valueOf(row) {
        return files[row.block][row.id]
    }

    function emptyFiles() {
        return {[SheetIds.rom]: {}, [SheetIds.storage]: {}}
    }

    function currentFiles() {
        const out = emptyFiles()
        fileRows.forEach(row => out[row.block][row.id] = valueOf(row).trim())
        return out
    }

    function problem() {
        return DeviceFormRules.Problem(boardId, currentFiles(), baseDir)
    }

    function setFile(row, value) {
        const next = emptyFiles()
        Object.keys(next).forEach(block => Object.assign(next[block], files[block]))
        next[row.block][row.id] = value
        files = next
        changed()
    }

    function setBoard(id) {
        files = DeviceFormRules.WithDefaults(id, files)
        boardId = id
        const suggested = nameFollowsBoard ? UserDeviceCreator.SuggestedName(BoardCatalog.DisplayName(id)) : ""
        if (suggested !== "") {
            if (nameField.text.trim() === "" || nameField.text === prefilled)
                nameField.text = suggested
            prefilled = suggested
        }
        changed()
    }

    function browse(row) {
        const value = valueOf(row)
        const dialog = fileDialog.createObject(fields, {
            "row": row,
            "nameFilters": row.nameFilters,
            "fileMode": row.storage ? FileDialog.SaveFile : FileDialog.OpenFile,
            "title": row.storage ? qsTr("Pick or name the %1 image").arg(row.name)
                                 : qsTr("Pick the %1").arg(row.name),
            "defaultSuffix": row.defaultSuffix,
            "currentFolder": FileAccess.BrowseFolder(value, baseDir)
        })
        if (row.storage)
            dialog.selectedFile = FileAccess.FileUrl(value, baseDir)
        dialog.open()
    }

    spacing: Theme.spaceL

    Component {
        id: fileDialog
        FileDialog {
            property var row
            options: FileDialog.DontConfirmOverwrite
            onAccepted: {
                const path = FileAccess.LocalPath(selectedFile)
                if (path !== "")
                    fields.setFile(row, FileAccess.PickedValue(path, fields.baseDir))
                destroy()
            }
            onRejected: destroy()
        }
    }

    SettingsGroup {
        SettingsRow {
            title: qsTr("Name")
            description: qsTr("How the device reads in the device list.")
            divider: false
            TextField {
                id: nameField
                width: parent.width
                enabled: fields.editable
                onTextEdited: fields.changed()
            }
        }
        SettingsRow {
            title: qsTr("Board")
            description: qsTr("The type of device to emulate.")
            ColumnLayout {
                width: parent.width
                Button {
                    Layout.fillWidth: true
                    enabled: fields.editable
                    text: BoardCatalog.BoardLabel(fields.boardId, qsTr("Pick a board"))
                    onClicked: fields.pickBoard()
                }
                SupportWarningLabel {
                    Layout.fillWidth: true
                    warning: BoardCatalog.SupportWarning(fields.boardId)
                }
            }
        }
    }

    Repeater {
        model: [{"title": qsTr("ROM"), "storage": false}, {"title": qsTr("Storage"), "storage": true}]
        delegate: SettingsGroup {
            id: card
            required property var modelData
            visible: fields.fileRows.some(r => r.storage === card.modelData.storage)

            SettingsRow {
                title: card.modelData.title
                divider: false
            }
            Repeater {
                model: fields.fileRows.filter(r => r.storage === card.modelData.storage)
                delegate: FileRow {
                    required property var modelData
                    row: modelData
                    value: fields.valueOf(modelData)
                    editable: fields.editable
                    onEdited: text => fields.setFile(modelData, text)
                    onBrowse: fields.browse(modelData)
                }
            }
        }
    }
}
