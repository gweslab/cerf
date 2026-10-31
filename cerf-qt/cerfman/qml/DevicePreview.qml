import QtQuick
import QtQuick.Effects
import QtQuick.Layouts
import CerfStyle

Item {
    id: preview
    property var row: null
    property bool detailed: false
    property bool actionEnabled: true
    property int radius: 0
    property real restHeight: height
    property real textOpacity: height < restHeight ? 0 : 1
    readonly property bool effects: !LegacyWindows.active && GraphicsInfo.api !== GraphicsInfo.Software
    readonly property string source: row !== null ? row.preview : ""
    readonly property var lines: {
        if (row === null)
            return []
        const name = [row.title, row.subtitle]
        return detailed ? name.concat([row.detail, row.status]) : name
    }
    signal launch()

    Behavior on textOpacity {
        NumberAnimation {
            duration: Theme.morphMs
        }
    }

    Item {
        id: content
        anchors.fill: parent
        clip: true
        layer.enabled: preview.effects && preview.radius > 0
        layer.effect: MultiEffect {
            maskEnabled: true
            maskSource: mask
            maskThresholdMin: 0.5
            maskSpreadAtMin: 1.0
        }

        Rectangle {
            anchors.fill: parent
            color: Theme.previewBackdrop
        }
        Image {
            id: backdrop
            anchors.fill: parent
            source: preview.source
            fillMode: Image.PreserveAspectCrop
            asynchronous: true
            visible: false
        }
        MultiEffect {
            anchors.fill: parent
            source: backdrop
            visible: preview.effects && preview.source !== ""
            opacity: Theme.previewBlurOpacity
            blurEnabled: true
            blur: 1.0
            blurMax: Theme.previewBlurRadius
        }
        Image {
            anchors.fill: parent
            source: preview.source
            fillMode: Image.PreserveAspectFit
            asynchronous: true
            visible: preview.source !== ""
        }
        Item {
            anchors.fill: parent
            opacity: preview.textOpacity

            Rectangle {
                id: scrimRamp
                anchors.left: parent.left
                anchors.right: parent.right
                y: parent.height * Theme.previewScrimStart
                height: parent.height * (Theme.previewScrimEnd - Theme.previewScrimStart)
                gradient: Gradient {
                    ScrimStop {
                        at: 0
                    }
                    ScrimStop {
                        at: 0.125
                    }
                    ScrimStop {
                        at: 0.25
                    }
                    ScrimStop {
                        at: 0.375
                    }
                    ScrimStop {
                        at: 0.5
                    }
                    ScrimStop {
                        at: 0.625
                    }
                    ScrimStop {
                        at: 0.75
                    }
                    ScrimStop {
                        at: 0.875
                    }
                    ScrimStop {
                        at: 1
                    }
                }
            }
            Rectangle {
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.top: scrimRamp.bottom
                anchors.bottom: parent.bottom
                color: Theme.previewScrim
            }
        }
    }

    ColumnLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.margins: Theme.spaceXL
        spacing: 0
        opacity: preview.textOpacity

        Repeater {
            model: preview.lines

            Marquee {
                id: line
                required property string modelData
                required property int index
                Layout.fillWidth: true
                visible: modelData !== ""
                text: modelData
                gap: Theme.spaceXL
                label: Component {
                    PreviewLabel {
                        emphasized: line.index === 0
                    }
                }
            }
        }
    }

    Item {
        id: mask
        anchors.fill: parent
        layer.enabled: true
        visible: false

        Rectangle {
            anchors.fill: parent
            radius: preview.radius
        }
    }

    GridLayout {
        id: chips
        readonly property bool wrapped: boardChip.visible && archChip.visible
                                        && boardChip.implicitWidth + columnSpacing + archChip.implicitWidth > width

        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: parent.top
        anchors.margins: Theme.spaceM
        columns: wrapped ? 1 : 3
        columnSpacing: Theme.spaceM
        rowSpacing: Theme.spaceS
        opacity: preview.textOpacity

        ColorChip {
            id: boardChip
            Layout.maximumWidth: chips.width
            text: preview.row !== null ? preview.row.board : ""
        }
        Item {
            visible: !chips.wrapped
            Layout.fillWidth: true
        }
        ColorChip {
            id: archChip
            text: preview.row !== null ? preview.row.arch : ""
        }
    }

    Item {
        id: actionArea
        anchors.fill: parent
        anchors.margins: Theme.spaceS

        PreviewActionButton {
            anchors.centerIn: parent
            discSize: Math.min(Theme.previewDiscSize, actionArea.height)
            runState: preview.row !== null ? preview.row.state : DeviceCards.offState
            enabled: preview.actionEnabled
            Accessible.name: preview.row !== null ? preview.row.launchLabel : ""
            onClicked: preview.launch()
        }
    }
}
