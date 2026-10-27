import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

PopupDialog {
    id: dialog
    required property var offer
    readonly property int changelogHeight: 280
    signal upgrade()

    function startUpgrade() {
        close()
        upgrade()
    }

    function openInBrowser() {
        close()
        DesktopShell.OpenLink(offer.htmlUrl)
    }

    preferredWidth: 600
    closePolicy: Popup.CloseOnEscape
    title: offer.title

    onClosed: destroy()

    DialogEnterShortcut {
        popup: dialog
        onActivated: dialog.startUpgrade()
    }

    rightToLeftButtons: [
        Button {
            text: qsTr("Cancel")
            onClicked: dialog.close()
        },
        Button {
            text: qsTr("Open in browser")
            onClicked: dialog.openInBrowser()
        },
        Button {
            text: qsTr("Upgrade")
            highlighted: true
            onClicked: dialog.startUpgrade()
        }
    ]

    ColumnLayout {
        anchors.fill: parent
        spacing: Theme.spaceM

        Label {
            Layout.fillWidth: true
            text: dialog.offer.message
            wrapMode: Text.Wrap
        }
        LinkLabel {
            Layout.fillWidth: true
            warning: true
            textFormat: Text.RichText
            text: qsTr("Your saved states will be broken - ") + HtmlText.Link(dialog.offer.warningUrl, qsTr("Learn more"))
        }
        Label {
            Layout.topMargin: Theme.spaceXS
            text: qsTr("Last version changelog:")
        }
        ScrollView {
            Layout.fillWidth: true
            Layout.fillHeight: true
            Layout.preferredHeight: dialog.changelogHeight

            LinkTextArea {
                text: dialog.offer.body
                textFormat: TextEdit.MarkdownText
            }
        }
    }
}
