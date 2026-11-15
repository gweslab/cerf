import QtQuick
import CerfStyle

Item {
    id: root
    property point at

    readonly property int arrowSize: 28
    readonly property real outlineReach: 1.5

    x: at.x - arrowSize * IconSources.cursorHotspot.x
    y: at.y - arrowSize * IconSources.cursorHotspot.y
    width: arrowSize
    height: arrowSize

    Repeater {
        model: 9
        delegate: SymbolIcon {
            required property int index
            x: (index % 3 - 1) * root.outlineReach
            y: (Math.floor(index / 3) - 1) * root.outlineReach
            name: IconSources.cursorSymbol
            size: root.arrowSize
            color: Theme.cursorOutline
        }
    }

    SymbolIcon {
        name: IconSources.cursorSymbol
        size: root.arrowSize
        color: Theme.cursorFill
    }
}
