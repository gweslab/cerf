import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

Page {
    id: tutorial
    readonly property bool last: slides.currentIndex === slides.count - 1
    signal finished()

    function end() {
        slides.setCurrentIndex(0)
        tutorial.finished()
    }

    function finish() {
        const error = TutorialState.Finish()
        if (error === "") {
            end()
            return
        }
        Dialogs.inform(tutorial, qsTr("Tutorial"), error, () => tutorial.end())
    }

    function next() {
        if (last)
            finish()
        else
            slides.incrementCurrentIndex()
    }

    function openLink(url) {
        DesktopShell.OpenLink(url)
    }

    footer: PageFooter {
        leading: [
            PageIndicator {
                count: slides.count
                currentIndex: slides.currentIndex
            }
        ]

        Button {
            visible: !tutorial.last
            text: qsTr("Skip")
            onClicked: tutorial.finish()
        }
        Button {
            text: tutorial.last ? qsTr("Continue") : qsTr("Next")
            highlighted: true
            onClicked: tutorial.next()
        }
    }

    SwipeView {
        id: slides
        anchors.fill: parent
        clip: true

        TutorialSlide {
            heading: qsTr("Welcome to %1!").arg(ProductLinks.productName)
            text: qsTr("Before your first run - let's walk over what to expect.")
            art: Component {
                Image {
                    source: IconSources.logo
                    sourceSize: Qt.size(width, height)
                    fillMode: Image.PreserveAspectFit
                }
            }
        }
        TutorialSlide {
            text: qsTr("Only a few people develop emulator in their spare time. "
                       + "Expect something to go wrong.<br><br>Devices with partial support crash and "
                       + "misbehave more than others.")
            art: Component {
                BetaStamp {}
            }
        }
        TutorialSlide {
            heading: qsTr("Touch input")
            text: {
                const lines = [qsTr("Most touch screen Windows CE devices are designed to be used with a stylus. "
                                    + "Your worst enemy is the calibration screen."),
                               qsTr("If your taps do not register, try <b>holding them longer</b> and <b>wiggle</b> "
                                    + "the pointer a bit.")]
                if (Theme.touchPlatform)
                    lines.push(qsTr("On a smartphone, prefer to complete the calibration with the cursor pointer. "
                                    + "A finger touch is read imprecise compared to a stylus it was designed for."))
                lines.push(qsTr("A wrong calibration misaligns all taps. Usually you can recalibrate in "
                                + "the Control Panel."))
                return lines.join("<br><br>")
            }
            art: Component {
                CalibrationArt {}
            }
        }
        TutorialSlide {
            heading: qsTr("Saves are temporary")
            text: qsTr("A future emulator update will most likely break your saved states.<br><br>"
                       + "Don't rely on it - before an upgrade do backups to external storage or use "
                       + "backup software for Windows CE.")
            art: Component {
                SavedStateArt {}
            }
        }
        TutorialSlide {
            heading: qsTr("You are all set")
            art: Component {
                DoneArt {}
            }

            Label {
                Layout.fillWidth: true
                text: qsTr("Get help from the community, or help the project:")
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.Wrap
            }
            Flow {
                Layout.alignment: Qt.AlignHCenter
                Layout.maximumWidth: parent.width
                spacing: Theme.spaceS

                Button {
                    text: qsTr("Website")
                    onClicked: tutorial.openLink(ProductLinks.websiteUrl)
                }
                Button {
                    text: qsTr("Discord")
                    onClicked: tutorial.openLink(ProductLinks.discordUrl)
                }
                Button {
                    text: qsTr("Support project")
                    onClicked: tutorial.openLink(ProductLinks.donateUrl)
                }
            }
            Label {
                Layout.fillWidth: true
                Layout.topMargin: Theme.spaceXL
                text: qsTr("%1 is brought to you by:").arg(ProductLinks.productName)
                horizontalAlignment: Text.AlignHCenter
                wrapMode: Text.Wrap
            }
            Marquee {
                Layout.fillWidth: true
                text: AboutModel.contributors
                separator: AboutModel.separator
            }
        }
    }
}
