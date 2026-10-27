import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

ColumnLayout {
    id: details
    required property var info
    property bool addonsEnabled: true
    readonly property bool hasDescription: info.description !== ""
    readonly property bool hasSource: info.source.name !== ""
    readonly property var unsupportedFeatures: info.unsupportedFeatures
    readonly property string notes: info.notes
    readonly property var packages: info.packages
    readonly property bool sourceLinked: hasSource && info.source.url !== ""
    signal packageAction(var pkg)

    spacing: Theme.spaceXL

    SideBlock {
        Layout.fillWidth: true
        visible: details.hasDescription || details.hasSource
        title: qsTr("Description")

        Label {
            Layout.fillWidth: true
            visible: details.hasDescription
            text: details.info.description
            wrapMode: Text.Wrap
        }
        RowLayout {
            Layout.fillWidth: true
            Layout.topMargin: details.hasDescription ? Theme.spaceM : 0
            visible: details.hasSource
            spacing: Theme.spaceM

            Label {
                Layout.alignment: Qt.AlignTop
                text: details.info.source.caption
            }
            LinkLabel {
                Layout.fillWidth: true
                textFormat: details.sourceLinked ? Text.RichText : Text.PlainText
                text: details.sourceLinked ? HtmlText.Link(details.info.source.url, details.info.source.name)
                                           : details.info.source.name
            }
        }
    }

    SideBlock {
        Layout.fillWidth: true
        visible: details.unsupportedFeatures.length > 0
        title: qsTr("Unsupported Features")

        Flow {
            Layout.fillWidth: true
            spacing: Theme.spaceM

            Repeater {
                model: details.unsupportedFeatures
                delegate: FeatureIcon {
                    required property var modelData
                    icon: modelData.icon
                    tip: modelData.tip
                }
            }
        }
    }

    SideBlock {
        Layout.fillWidth: true
        visible: details.notes !== ""
        title: qsTr("Notes")
        warn: true

        Label {
            Layout.fillWidth: true
            text: details.notes
            wrapMode: Text.Wrap
        }
    }

    SideBlock {
        Layout.fillWidth: true
        visible: details.packages.length > 0
        title: qsTr("Add-ons")

        Repeater {
            model: details.packages
            delegate: ColumnLayout {
                id: entry
                required property var modelData
                required property int index
                Layout.fillWidth: true
                spacing: 0

                Label {
                    Layout.topMargin: Theme.spaceXS
                    visible: entry.index === 0
                             || details.packages[entry.index - 1].categoryLabel !== entry.modelData.categoryLabel
                    text: entry.modelData.categoryLabel
                }
                RowLayout {
                    Layout.fillWidth: true
                    spacing: Theme.spaceXS

                    Label {
                        Layout.fillWidth: true
                        text: entry.modelData.name
                        wrapMode: Text.Wrap
                    }
                    Loader {
                        sourceComponent: entry.modelData.installs ? installButton : deleteButton
                    }
                    Component {
                        id: installButton
                        Button {
                            text: entry.modelData.actionLabel
                            enabled: details.addonsEnabled
                            onClicked: details.packageAction(entry.modelData)
                        }
                    }
                    Component {
                        id: deleteButton
                        DangerButton {
                            text: entry.modelData.actionLabel
                            enabled: details.addonsEnabled
                            onClicked: details.packageAction(entry.modelData)
                        }
                    }
                }
            }
        }
    }
}
