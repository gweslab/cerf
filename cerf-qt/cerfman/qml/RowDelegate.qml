import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

ItemDelegate {
    id: row
    property int columns: -1
    default property alias cells: grid.data

    contentItem: GridLayout {
        id: grid
        columns: row.columns
        columnSpacing: Theme.spaceXL
        rowSpacing: 0
    }
}
