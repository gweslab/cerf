import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

Control {
    id: heading
    property string text: ""
    property string caption: ""
    property var arches: []
    property bool narrow: false

    component Chips: RowLayout {
        id: chips
        property var arches: []

        spacing: Theme.spaceS

        Repeater {
            model: chips.arches

            ColorChip {
                required property var modelData
                Layout.minimumWidth: implicitWidth
                text: modelData
            }
        }
    }

    Layout.fillWidth: true
    padding: 0

    contentItem: RowLayout {
        spacing: Theme.spaceS

        ColumnLayout {
            Layout.fillWidth: true
            spacing: 0

            RowLayout {
                Layout.fillWidth: true
                spacing: Theme.spaceS

                StrongLabel {
                    Layout.fillWidth: heading.narrow
                    text: heading.text
                    wrapMode: Text.Wrap
                }
                Chips {
                    visible: !heading.narrow
                    arches: heading.arches
                }
                Item {
                    Layout.fillWidth: true
                    visible: !heading.narrow
                }
            }
            CaptionLabel {
                Layout.fillWidth: true
                visible: text !== ""
                text: heading.caption
                wrapMode: Text.Wrap
            }
        }
        Chips {
            visible: heading.narrow
            arches: heading.arches
        }
    }
}
