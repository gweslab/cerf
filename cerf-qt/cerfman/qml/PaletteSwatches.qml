import QtQuick
import CerfStyle

Rectangle {
    id: swatches
    property var colors: []
    readonly property int sparseLimit: 16
    readonly property int denseColumns: 64
    readonly property int denseCell: 3
    readonly property int sparseCell: 12
    readonly property bool dense: colors.length > sparseLimit

    visible: colors.length > 0
    color: Theme.divider
    implicitWidth: grid.implicitWidth + 2 * Theme.hairline
    implicitHeight: grid.implicitHeight + 2 * Theme.hairline

    Grid {
        id: grid
        anchors.centerIn: parent
        columns: swatches.dense ? swatches.denseColumns : Math.max(1, swatches.colors.length)
        spacing: Theme.hairline

        Repeater {
            model: swatches.colors

            Rectangle {
                required property color modelData
                width: swatches.dense ? swatches.denseCell : swatches.sparseCell
                height: width
                color: modelData
            }
        }
    }
}
