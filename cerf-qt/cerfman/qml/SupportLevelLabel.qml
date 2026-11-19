pragma ComponentBehavior: Bound
import QtQuick
import QtQuick.Layouts
import CerfStyle

Flow {
    id: support
    property var clauses: []
    readonly property var toneColors: ({
        "good": Theme.success,
        "caution": Theme.warn,
        "bad": Theme.danger
    })

    visible: clauses.length > 0
    spacing: Theme.spaceM

    Repeater {
        model: support.clauses
        delegate: RowLayout {
            id: clause
            required property var modelData

            width: Math.min(implicitWidth, support.width)
            spacing: Theme.spaceXS

            Dot {
                Layout.alignment: Qt.AlignTop
                Layout.topMargin: (metrics.height - diameter) / 2
                color: support.toneColors[clause.modelData.tone]
            }
            CaptionLabel {
                id: label
                Layout.fillWidth: true
                text: clause.modelData.text
                wrapMode: Text.Wrap
            }
            FontMetrics {
                id: metrics
                font: label.font
            }
        }
    }
}
