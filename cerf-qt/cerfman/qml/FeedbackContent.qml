import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

ColumnLayout {
    id: content
    property bool compact: false
    property var issues: []
    property string note: FeedbackModel.loadingText
    property bool requested: false

    function load() {
        if (requested || !visible)
            return
        requested = true
        FeedbackModel.Load()
    }

    spacing: Theme.spaceL
    onVisibleChanged: load()
    Component.onCompleted: load()

    Connections {
        target: FeedbackModel
        function onLoaded(issues, note) {
            content.issues = issues
            content.note = note
        }
    }

    RowLayout {
        Layout.fillWidth: true
        Layout.topMargin: Theme.spaceXL
        Layout.leftMargin: Theme.spaceXL
        Layout.rightMargin: Theme.spaceXL
        spacing: Theme.spaceXL

        Label {
            Layout.fillWidth: true
            text: FeedbackModel.header
            wrapMode: Text.Wrap
        }
        Button {
            text: FeedbackModel.createText
            highlighted: true
            onClicked: DesktopShell.OpenLink(FeedbackModel.createUrl)
        }
    }

    TableList {
        Layout.fillWidth: true
        Layout.fillHeight: true
        headerVisible: !content.compact
        columns: [
            ColumnTitle {
                Layout.fillWidth: true
                text: qsTr("Issue")
            },
            ColumnTitle {
                text: qsTr("Reactions")
            }
        ]

        TableListView {
            model: content.issues

            delegate: RowDelegate {
                id: issue
                required property var modelData
                width: ListView.view.width
                onClicked: DesktopShell.OpenLink(issue.modelData.url)

                Label {
                    Layout.fillWidth: true
                    text: issue.modelData.label
                    wrapMode: Text.Wrap
                }
                SecondaryLabel {
                    text: issue.modelData.reactions
                }

                HoverHandler {
                    cursorShape: Qt.PointingHandCursor
                }
            }

            SecondaryLabel {
                anchors.left: parent.left
                anchors.right: parent.right
                anchors.margins: Theme.spaceXL
                visible: content.note !== ""
                text: content.note
                wrapMode: Text.Wrap
            }
        }
    }
}
