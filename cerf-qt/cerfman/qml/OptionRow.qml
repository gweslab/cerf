import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

GridLayout {
    id: row
    property string title
    property string description
    property bool wideControl: true
    readonly property bool stacked: columns === 1
    default property alias control: slot.data
    signal anchorActivated(string link)

    columns: wideControl ? Theme.rowColumns(width, 2) : 2
    columnSpacing: Theme.spaceXXXL
    rowSpacing: Theme.spaceS

    ColumnLayout {
        Layout.fillWidth: true
        spacing: Theme.spaceXXS

        Label {
            Layout.fillWidth: true
            text: row.title
            wrapMode: Text.Wrap
        }
        CaptionLabel {
            Layout.fillWidth: true
            visible: row.description !== ""
            text: row.description
            textFormat: Text.StyledText
            wrapMode: Text.Wrap
            onAnchorActivated: link => row.anchorActivated(link)
        }
    }

    Item {
        id: slot
        Layout.fillWidth: row.stacked
        Layout.preferredWidth: implicitWidth
        Layout.alignment: Qt.AlignVCenter | (row.stacked ? Qt.AlignLeft : Qt.AlignRight)
        implicitWidth: row.wideControl ? Theme.optionControlWidth : childrenRect.width
        implicitHeight: childrenRect.height
    }
}
