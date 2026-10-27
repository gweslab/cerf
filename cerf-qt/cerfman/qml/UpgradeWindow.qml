import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

PageWindow {
    id: host
    required property QtObject model
    property bool finished: false
    readonly property int iconSize: 32
    readonly property int logLines: 12
    readonly property int fixedWidth: 400

    title: model.heading
    modal: false
    visible: true
    width: fixedWidth
    height: column.implicitHeight
    minimumWidth: fixedWidth
    maximumWidth: fixedWidth
    minimumHeight: column.implicitHeight

    onClosing: close => close.accepted = host.finished

    Connections {
        target: host.model
        function onLogLine(line) {
            log.append(line)
        }
        function onProgress(done, total) {
            progress.done = done
            progress.total = total
        }
        function onRetryRequested(title, message) {
            Dialogs.retry(host.contentItem, title, message, again => host.model.AnswerRetry(again))
        }
        function onFailed(title, message) {
            progress.running = false
            Dialogs.inform(host.contentItem, title, message, () => {
                host.finished = true
                host.close()
                host.model.Close()
            })
        }
    }

    BandedContent {
        id: column
        anchors.fill: parent
        contentSpacing: Theme.spaceXL

        RowLayout {
            spacing: Theme.spaceXL

            Image {
                source: IconSources.Asset("cerf_setup")
                sourceSize.width: host.iconSize
                sourceSize.height: host.iconSize
            }
            Label {
                Layout.fillWidth: true
                text: host.model.heading
                wrapMode: Text.Wrap
            }
        }

        ScrollView {
            id: logView
            Layout.fillWidth: true
            Layout.preferredHeight: metrics.lineSpacing * host.logLines + log.topPadding + log.bottomPadding
                                    + logView.topPadding + logView.bottomPadding

            TextArea {
                id: log
                readOnly: true
                selectByMouse: true
                wrapMode: TextEdit.WrapAnywhere
            }
        }

        TransferProgress {
            id: progress
            Layout.fillWidth: true
        }
    }

    FontMetrics {
        id: metrics
        font: log.font
    }
}
