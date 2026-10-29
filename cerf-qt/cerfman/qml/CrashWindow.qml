import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

PageWindow {
    id: host
    property bool mobile: false
    property string crashLogPath
    readonly property bool narrow: width < Theme.compactWidth
    readonly property int buttonWidth: 180

    title: qsTr("Unexpected error - %1").arg(ProductLinks.productName)
    modal: false
    width: 680
    height: 640
    minimumWidth: mobile ? 0 : 544
    minimumHeight: mobile ? 0 : 448

    function goBack() {
        host.close()
        return true
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

    Shortcut {
        sequence: "Escape"
        onActivated: host.close()
    }
    EnterShortcut {
        onActivated: host.close()
    }

    footer: mobile ? null : exitFooter

    PageFooter {
        id: exitFooter
        visible: !host.mobile

        Button {
            text: qsTr("Exit")
            highlighted: true
            onClicked: host.close()
        }
    }

    ColumnLayout {
        anchors.fill: parent
        spacing: 0

        PageBar {
            Layout.fillWidth: true
            title: qsTr("Something went wrong")
            backVisible: host.mobile
            onBack: host.close()
        }

        ColumnLayout {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.margins: host.narrow ? Theme.spaceXL : Theme.spaceXXXL
            spacing: Theme.spaceL

            ScrollView {
                Layout.fillWidth: true
                Layout.fillHeight: true

                CodeText {
                    text: CrashReportModel.DumpText(host.crashLogPath)
                }
            }

            LinkLabel {
                Layout.fillWidth: true
                text: qsTr("If you think you have found an actual bug - %1.  Maybe someone has already reported that - "
                           + "you can upvote it.").arg(host.feedbackLink(qsTr("see GitHub issues")))
                onAnchorActivated: host.openFeedback()
            }

            GridLayout {
                Layout.fillWidth: true
                columns: host.narrow ? 1 : 2
                columnSpacing: Theme.spaceXXL
                rowSpacing: Theme.spaceL

                ColumnLayout {
                    Layout.alignment: Qt.AlignTop
                    Layout.fillWidth: host.narrow
                    spacing: Theme.spaceS

                    Button {
                        Layout.fillWidth: host.narrow
                        Layout.preferredWidth: host.narrow ? -1 : host.buttonWidth
                        text: qsTr("Log (%1)").arg(CrashReportModel.SizeLabel(CrashReportModel.logPath))
                        enabled: CrashReportModel.Exists(CrashReportModel.logPath)
                        onClicked: host.showFile(CrashReportModel.logPath)
                    }
                    Button {
                        Layout.fillWidth: host.narrow
                        Layout.preferredWidth: host.narrow ? -1 : host.buttonWidth
                        text: qsTr("Crash Dump (%1)").arg(CrashReportModel.SizeLabel(host.crashLogPath))
                        enabled: CrashReportModel.Exists(host.crashLogPath)
                        onClicked: host.showFile(host.crashLogPath)
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
                        text: host.mobile
                              ? qsTr("You must attach both log files - tap to share. Log files might include "
                                     + "<b>personal data</b> like folder paths or computer specs. "
                                     + "<b>GitHub profile is required</b>")
                              : qsTr("You must attach both log files - click to locate. Log files might include "
                                     + "<b>personal data</b> like folder paths or computer specs. "
                                     + "<b>GitHub profile is required</b>")
                        textFormat: Text.StyledText
                        wrapMode: Text.Wrap
                    }
                }
            }
        }
    }
}
