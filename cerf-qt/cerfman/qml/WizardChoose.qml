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
        property bool tall: false

        Layout.fillWidth: true
        Layout.fillHeight: tall
        Layout.preferredWidth: 1
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

    GridLayout {
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.top: page.mobile ? undefined : parent.top
        anchors.bottom: page.mobile ? undefined : parent.bottom
        anchors.verticalCenter: page.mobile ? parent.verticalCenter : undefined
        anchors.margins: Theme.spaceXL
        columns: 2
        columnSpacing: Theme.spaceXL

        ChoiceTile {
            tall: !page.mobile
            symbol: "folder_open"
            title: qsTr("New device")
            description: qsTr("Create a device from your local ROM")
            enabled: !ManagerOperations.busy
            onClicked: page.localRom()
        }
        ChoiceTile {
            tall: !page.mobile
            symbol: "download"
            title: qsTr("Download ROMs")
            description: qsTr("Get ready-to-run ROMs from public sources")
            enabled: !ManagerOperations.busy && !BundleCatalog.loading
            onClicked: page.download()
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
