import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

Page {
    id: page
    property bool mobile: false
    property bool closable: false
    signal localRom()
    signal download()
    signal cancel()

    component ChoiceTile: WizardTile {
        property bool bounded: false
        readonly property int boundedSize: 260

        Layout.fillWidth: true
        Layout.fillHeight: bounded
        Layout.preferredWidth: bounded ? boundedSize : 1
        Layout.preferredHeight: bounded ? boundedSize : -1
    }

    header: page.mobile ? mobileBar : null
    footer: page.mobile ? null : desktopFooter

    PageBar {
        id: mobileBar
        visible: page.mobile
        title: qsTr("New")
        backVisible: page.closable
        onBack: page.cancel()
    }

    Item {
        anchors.fill: parent
        anchors.margins: Theme.spaceXL

        GridLayout {
            anchors.centerIn: parent
            width: page.mobile ? parent.width : Math.min(implicitWidth, parent.width)
            height: page.mobile ? implicitHeight : Math.min(implicitHeight, parent.height)
            columns: 2
            columnSpacing: Theme.spaceXL

            ChoiceTile {
                bounded: !page.mobile
                symbol: "folder_open"
                title: qsTr("New device")
                description: qsTr("Create a device from your local ROM")
                enabled: !ManagerOperations.busy
                onClicked: page.localRom()
            }
            ChoiceTile {
                bounded: !page.mobile
                symbol: "download"
                title: qsTr("Download ROMs")
                description: qsTr("Get ready-to-run ROMs from public sources")
                enabled: !ManagerOperations.busy && !BundleCatalog.loading
                onClicked: page.download()
            }
        }
    }

    PageFooter {
        id: desktopFooter
        visible: !page.mobile

        Button {
            text: qsTr("Cancel")
            onClicked: page.cancel()
        }
    }
}
