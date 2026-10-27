import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

ColumnLayout {
    id: fileRow
    property var row
    property alias value: path.value
    property alias editable: path.editable
    signal edited(string text)
    signal browse()

    Layout.fillWidth: true
    Layout.leftMargin: Theme.spaceXL
    Layout.rightMargin: Theme.spaceXL
    Layout.bottomMargin: Theme.spaceM
    spacing: Theme.spaceXS

    Label {
        text: fileRow.row.name
    }
    PathField {
        id: path
        onEdited: text => fileRow.edited(text)
        onBrowse: fileRow.browse()
    }
    CaptionLabel {
        Layout.fillWidth: true
        visible: fileRow.row.note !== ""
        text: fileRow.row.note
        wrapMode: Text.Wrap
    }
}
