import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

ColumnLayout {
    id: cell
    property alias text: main.text
    property alias wrapMode: main.wrapMode
    property alias caption: captionLabel.text
    property bool folded: false

    Layout.fillWidth: true
    spacing: 0

    Label {
        id: main
        Layout.fillWidth: true
        wrapMode: Text.Wrap
    }
    CaptionLabel {
        id: captionLabel
        Layout.fillWidth: true
        visible: cell.folded && text !== ""
        wrapMode: Text.Wrap
    }
}
