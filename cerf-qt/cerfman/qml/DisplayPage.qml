import QtQuick
import QtQuick.Layouts
import CerfStyle

SheetPage {
    id: page
    signal bppHelp()

    DisplayFields {
        sheet: page.sheet
        editable: page.editable
        onBppHelp: page.bppHelp()
    }
}
