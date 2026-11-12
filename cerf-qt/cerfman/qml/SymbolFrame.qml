import QtQuick
import QtQuick.Layouts
import CerfStyle

RowLayout {
    id: frame
    property string symbol
    property color symbolColor
    property string asset
    default property alias content: body.data

    spacing: Theme.spaceXL

    SymbolIcon {
        Layout.alignment: Qt.AlignTop
        visible: frame.symbol !== ""
        name: frame.symbol
        size: frame.symbol !== "" ? Theme.dialogSymbolSize : 0
        color: frame.symbolColor
    }
    Image {
        Layout.alignment: Qt.AlignTop
        visible: frame.asset !== ""
        source: frame.asset !== "" ? IconSources.Asset(frame.asset) : ""
        sourceSize: Qt.size(Theme.dialogSymbolSize, Theme.dialogSymbolSize)
    }
    ColumnLayout {
        id: body
        Layout.fillWidth: true
    }
}
