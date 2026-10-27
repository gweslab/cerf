import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

RowLayout {
    id: field
    property string value: ""
    property bool editable: true
    signal edited(string text)
    signal browse()

    Layout.fillWidth: true
    spacing: Theme.spaceS

    TextField {
        Layout.fillWidth: true
        enabled: field.editable
        text: FileAccess.DisplayText(field.value)
        onTextEdited: field.edited(text)
    }
    Button {
        enabled: field.editable
        text: qsTr("Browse…")
        onClicked: field.browse()
    }
}
