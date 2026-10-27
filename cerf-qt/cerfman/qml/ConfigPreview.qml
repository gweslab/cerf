import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

ColumnLayout {
    id: preview
    property QtObject sheet: null
    readonly property var blocks: sheet !== null ? sheet.preview : []
    readonly property bool stacked: blockRepeater.count > 0 && blockRepeater.itemAt(0) !== null
                                    && blocks.some(b => !fit.fits(b.rows, blockRepeater.itemAt(0).bodyWidth))
    signal open(string page)

    spacing: Theme.spaceXL

    KeyValueRows {
        id: fit
        visible: false
    }

    Repeater {
        id: blockRepeater
        model: preview.blocks
        delegate: SideBlock {
            id: block
            required property var modelData
            Layout.fillWidth: true
            title: modelData.title
            clickable: true
            onClicked: preview.open(modelData.key)

            KeyValueRows {
                Layout.fillWidth: true
                rows: block.modelData.rows
                stacked: preview.stacked
            }
            SupportWarningLabel {
                Layout.fillWidth: true
                Layout.topMargin: Theme.spaceS
                warning: block.modelData.warning
            }
        }
    }
}
