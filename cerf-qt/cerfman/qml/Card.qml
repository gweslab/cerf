import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

Pane {
    id: card
    default property alias content: column.data

    padding: Theme.spaceL
    hoverEnabled: false

    background: CardBackground {
        hovered: card.hovered
    }

    ColumnLayout {
        id: column
        anchors.fill: parent
        spacing: card.spacing
    }
}
