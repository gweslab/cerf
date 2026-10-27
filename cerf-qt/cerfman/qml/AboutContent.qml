import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

ScrollPage {
    id: content
    property string deviceLine: ""
    readonly property QtObject about: AboutModel

    function openLicenses() {
        const problem = about.OpenLicenses()
        if (problem !== "")
            Dialogs.inform(content, about.licensesTitle, problem)
    }

    margins: 0

    BandedContent {
        Layout.fillWidth: true
        contentSpacing: Theme.spaceL

        ColumnLayout {
            spacing: 0

            RowLayout {
                spacing: Theme.spaceXS

                TitleLabel {
                    level: TitleLabel.Display
                    text: ProductLinks.productName
                }
                SecondaryLabel {
                    Layout.alignment: Qt.AlignTop
                    text: content.about.versionLabel
                }
            }
            SecondaryLabel {
                Layout.fillWidth: true
                visible: content.about.build !== ""
                text: content.about.build
                wrapMode: Text.Wrap
            }
        }

        LinkLabel {
            Layout.fillWidth: true
            dim: true
            text: content.about.linksHtml
        }

        Label {
            Layout.fillWidth: true
            visible: content.deviceLine !== ""
            text: content.deviceLine
            wrapMode: Text.Wrap
        }

        ColumnLayout {
            Layout.fillWidth: true
            spacing: Theme.spaceXXS

            SecondaryLabel {
                text: content.about.contributorsHeader
            }
            Marquee {
                Layout.fillWidth: true
                text: content.about.contributors
                separator: content.about.separator
            }
        }

        LinkLabel {
            Layout.fillWidth: true
            text: content.about.copyright + HtmlText.Link(content.about.authorUrl, content.about.author)
        }

        Button {
            text: content.about.licensesTitle
            onClicked: content.openLicenses()
        }
    }
}
