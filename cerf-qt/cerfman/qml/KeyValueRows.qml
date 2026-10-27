import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

Column {
    id: grid
    property var rows: []
    property bool stacked: false
    readonly property int keyGap: Theme.spaceXL
    readonly property real half: Math.floor(width / 2)

    spacing: stacked ? Theme.spaceXS : 0

    function fits(list, available) {
        const half = Math.floor(available / 2)
        return list.every(row => metrics.advanceWidth(row[0]) <= half - keyGap
                          && row[1].split(/\s+/).every(word => metrics.advanceWidth(word) <= half))
    }

    FontMetrics {
        id: metrics
    }

    Repeater {
        model: grid.rows
        delegate: GridLayout {
            required property var modelData

            width: grid.width
            columns: grid.stacked ? 1 : 2
            columnSpacing: 0
            rowSpacing: 0

            Label {
                Layout.fillWidth: grid.stacked
                Layout.preferredWidth: grid.stacked ? 0 : grid.half
                Layout.alignment: Qt.AlignTop
                rightPadding: grid.stacked ? 0 : grid.keyGap
                text: parent.modelData[0]
                wrapMode: Text.Wrap
            }
            SecondaryLabel {
                Layout.fillWidth: true
                Layout.preferredWidth: 0
                Layout.alignment: Qt.AlignTop
                text: parent.modelData[1]
                wrapMode: Text.Wrap
            }
        }
    }
}
