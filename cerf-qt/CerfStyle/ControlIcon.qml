import QtQuick

Image {
    property url symbol
    property color tint
    property size iconSize

    visible: symbol.toString() !== ""
    source: visible ? SymbolTint.Url(symbol, tint) : ""
    sourceSize: iconSize
}
