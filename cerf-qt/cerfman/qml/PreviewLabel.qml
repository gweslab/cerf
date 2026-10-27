import QtQuick
import QtQuick.Controls
import CerfStyle

Label {
    property bool emphasized: false

    color: emphasized ? Theme.previewText : Theme.previewTextDim
    font.pixelSize: emphasized ? Theme.tileTitleSize : Theme.captionSize
    font.bold: emphasized
    elide: Text.ElideRight
    maximumLineCount: 1
}
