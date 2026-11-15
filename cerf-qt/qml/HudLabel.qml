import QtQuick
import CerfStyle

Text {
    property string family
    property int pixelSize
    property bool bold
    property color ink

    font.family: family
    font.pixelSize: pixelSize
    font.bold: bold
    color: ink
    textFormat: Text.PlainText
    wrapMode: Text.NoWrap
    fontSizeMode: Text.HorizontalFit
    minimumPixelSize: Theme.fitMinimumPixelSize
    horizontalAlignment: Text.AlignHCenter
    verticalAlignment: Text.AlignVCenter
}
