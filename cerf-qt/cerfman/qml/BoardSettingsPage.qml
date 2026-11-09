import QtQuick
import QtQuick.Layouts
import CerfStyle

SheetPage {
    id: page
    signal pickBoard(string current)

    function setBoard(id) {
        fields.setBoard(id)
    }

    function push() {
        const files = fields.currentFiles()
        sheet.SetValue(SheetIds.boardId, fields.boardId)
        sheet.SetValue(SheetIds.name, fields.name.trim())
        sheet.SetValue(SheetIds.rom, files[SheetIds.rom])
        sheet.SetValue(SheetIds.storage, files[SheetIds.storage])
    }

    BoardRomFields {
        id: fields
        Layout.fillWidth: true
        editable: page.editable
        baseDir: page.sheet.deviceDirectory
        boardConfig: page.sheet.boardConfig
        onPickBoard: page.pickBoard(fields.boardId)
        onChanged: page.push()
        onConfigPicked: (id, value) => page.sheet.SetBoardConfig(id, value)

        Component.onCompleted: {
            const values = page.sheet.values
            files = DeviceFormRules.WithDefaults(page.sheet.boardId, {[SheetIds.rom]: values[SheetIds.rom],
                                                                      [SheetIds.storage]: values[SheetIds.storage]})
            boardId = page.sheet.boardId
            name = values[SheetIds.name]
        }
    }
}
