import QtQuick
import QtQuick.Layouts
import CerfStyle

SymbolFrame {
    id: message
    property string text
    property string level
    property int textFormat: TextEdit.PlainText

    symbol: level
    symbolColor: level === "error" ? Theme.danger : Theme.warn

    MessageText {
        Layout.fillWidth: true
        text: message.text
        textFormat: message.textFormat
    }
}
