import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

ScrollPage {
    id: slide
    property string heading: ""
    property string text: ""
    property Component art: null
    default property alias extra: extras.data
    readonly property int artSize: 144
    readonly property int textWidth: 480

    implicitWidth: textWidth
    centered: true

    ColumnLayout {
        Layout.alignment: Qt.AlignHCenter
        Layout.fillWidth: true
        Layout.fillHeight: false
        Layout.maximumWidth: slide.textWidth
        spacing: Theme.spaceXL

        Loader {
            Layout.alignment: Qt.AlignHCenter
            Layout.preferredWidth: slide.artSize
            Layout.preferredHeight: slide.artSize
            Layout.bottomMargin: Theme.spaceXL
            sourceComponent: slide.art
        }
        TitleLabel {
            Layout.fillWidth: true
            visible: text !== ""
            level: TitleLabel.Headline
            text: slide.heading
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.Wrap
        }
        Label {
            Layout.fillWidth: true
            visible: text !== ""
            text: slide.text
            textFormat: Text.StyledText
            horizontalAlignment: Text.AlignHCenter
            wrapMode: Text.Wrap
        }
        ColumnLayout {
            id: extras
            Layout.fillWidth: true
            Layout.fillHeight: false
            spacing: Theme.spaceL
        }
    }
}
