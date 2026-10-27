import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

PageWindow {
    id: host
    readonly property int iconSize: 48
    readonly property int buttonWidth: 180

    title: qsTr("Unexpected error - %1").arg(ProductLinks.productName)
    modal: false
    width: 680
    height: 640
    minimumWidth: 544
    minimumHeight: 448

    Shortcut {
        sequence: "Escape"
        onActivated: host.close()
    }
    EnterShortcut {
        onActivated: host.close()
    }

    function openFeedback() {
        Dialogs.openSettings(host, SheetIds.settingsFeedbackPage)
    }

    function feedbackLink(text) {
        return HtmlText.Link(SheetIds.settingsFeedbackPage, text)
    }

    function showFile(path) {
        const problem = CrashReportModel.ShowFile(path)
        if (problem !== "")
            Dialogs.inform(host.contentItem, qsTr("Show file"), problem)
    }

    footer: PageFooter {
        Button {
            text: qsTr("Exit")
            highlighted: true
            onClicked: host.close()
        }
    }

    ColumnLayout {
        anchors.fill: parent
        anchors.margins: Theme.spaceXXXL
        spacing: Theme.spaceL

        RowLayout {
            spacing: Theme.spaceXL

            Image {
                source: IconSources.errorImage
                sourceSize.width: host.iconSize
                sourceSize.height: host.iconSize
            }
            TitleLabel {
                level: TitleLabel.Display
                text: qsTr("Something went wrong")
            }
        }

        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true

            CodeText {
                text: CrashReportModel.DumpText()
            }
        }

        LinkLabel {
            Layout.fillWidth: true
            text: qsTr("If you think you have found an actual bug - %1.  Maybe someone has already reported that - "
                       + "you can upvote it.").arg(host.feedbackLink(qsTr("see GitHub issues")))
            onAnchorActivated: host.openFeedback()
        }

        RowLayout {
            Layout.fillWidth: true
            spacing: Theme.spaceXXL

            ColumnLayout {
                Layout.alignment: Qt.AlignTop
                spacing: Theme.spaceS

                Button {
                    Layout.preferredWidth: host.buttonWidth
                    text: qsTr("Log (%1)").arg(CrashReportModel.SizeLabel(CrashReportModel.logPath))
                    enabled: CrashReportModel.Exists(CrashReportModel.logPath)
                    onClicked: host.showFile(CrashReportModel.logPath)
                }
                Button {
                    Layout.preferredWidth: host.buttonWidth
                    text: qsTr("Crash Dump (%1)").arg(CrashReportModel.SizeLabel(CrashReportModel.crashLogPath))
                    enabled: CrashReportModel.Exists(CrashReportModel.crashLogPath)
                    onClicked: host.showFile(CrashReportModel.crashLogPath)
                }
            }
            ColumnLayout {
                Layout.fillWidth: true
                spacing: Theme.spaceS

                LinkLabel {
                    Layout.fillWidth: true
                    text: qsTr("Or you can %1.").arg(host.feedbackLink(qsTr("create your own ticket")))
                    onAnchorActivated: host.openFeedback()
                }
                Label {
                    Layout.fillWidth: true
                    text: qsTr("You must attach both log files - click to locate. Log files might include "
                               + "<b>personal data</b> like folder paths or computer specs. "
                               + "<b>GitHub profile is required</b>")
                    textFormat: Text.StyledText
                    wrapMode: Text.Wrap
                }
            }
        }
    }
}
