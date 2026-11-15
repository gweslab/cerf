import QtQuick
import QtQuick.Layouts
import CerfStyle

PopupDialog {
    id: dialog
    required property var offer
    readonly property int changelogHeight: 280
    signal upgrade()

    function proceed() {
        close()
        if (offer.upgradable)
            upgrade()
        else
            DesktopShell.OpenLink(offer.downloadUrl)
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
        onActivated: dialog.proceed()
    }

    rightToLeftButtons: [
        Button {
            text: qsTr("Cancel")
            onClicked: dialog.close()
        },
        Button {
            visible: dialog.offer.upgradable
            text: qsTr("Manual download")
            onClicked: dialog.openInBrowser()
        },
        Button {
            text: dialog.offer.upgradable ? qsTr("Upgrade") : qsTr("Download")
            highlighted: true
            onClicked: dialog.proceed()
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
            text: qsTr("Your saved states might degrade or lose data. ") + HtmlText.Link(dialog.offer.warningUrl, qsTr("Learn more"))
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
