import QtQuick
import QtQuick.Controls

TabBar {
    id: bar
    readonly property int devicesPage: 0
    readonly property int newPage: 1
    readonly property int settingsPage: 2
    property bool inlinePages: true
    property int page: devicesPage
    signal newRequested()
    signal settingsRequested()

    position: TabBar.Footer
    currentIndex: page

    function show(index) {
        page = index
        currentIndex = index
    }

    onCurrentIndexChanged: {
        if (currentIndex === page)
            return
        if (currentIndex !== devicesPage && !inlinePages) {
            const requested = currentIndex
            currentIndex = page
            if (requested === newPage)
                newRequested()
            else
                settingsRequested()
            return
        }
        page = currentIndex
    }

    TabButton {
        text: qsTr("My Devices")
        icon.source: IconSources.Icon("devices")
        display: AbstractButton.TextUnderIcon
    }
    TabButton {
        text: qsTr("New")
        icon.source: IconSources.newIcon
        display: AbstractButton.TextUnderIcon
    }
    TabButton {
        text: qsTr("Settings")
        icon.source: IconSources.settingsIcon
        display: AbstractButton.TextUnderIcon
    }
}
