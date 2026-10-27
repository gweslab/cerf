import QtQuick
import QtQuick.Controls
import QtQuick.Layouts

Page {
    id: home
    required property QtObject flows
    required property QtObject commands
    property bool mobile: false
    property bool inlinePages: false
    readonly property int page: mobile ? mobileNav.page : mobileNav.devicesPage
    property alias model: devicesScreen.model
    property alias listBottomInset: devicesScreen.listBottomInset
    property alias compact: devicesScreen.compact
    property alias selectedName: devicesScreen.selectedName
    property alias selectedRow: devicesScreen.selectedRow
    property alias revision: devicesScreen.revision
    property alias installed: devicesScreen.installed
    readonly property string query: mobile ? mobileTop.query : devicesScreen.query
    property int bundleUpdates: 0
    property string cerfStatus: ""
    property bool cerfAvailable: false
    property bool busy: false

    function showNewTab() {
        mobileNav.show(mobileNav.newPage)
    }

    function showSettingsTab() {
        mobileNav.show(mobileNav.settingsPage)
    }

    function goBack() {
        if (page === mobileNav.devicesPage)
            return false
        if (page === mobileNav.newPage && wizard.item.goBack())
            return true
        if (page === mobileNav.settingsPage && settingsTab.item.goBack())
            return true
        mobileNav.show(mobileNav.devicesPage)
        return true
    }

    header: mobile && page === mobileNav.devicesPage ? mobileTop : null
    footer: mobile ? mobileNav : null

    MobileTopBar {
        id: mobileTop
        visible: home.mobile && home.page === mobileNav.devicesPage
        bundleUpdates: home.bundleUpdates
        cerfStatus: home.cerfStatus
        cerfAvailable: home.cerfAvailable
        onUpdateBundles: home.commands.updateAll()
        onOpenCerfUpdate: home.commands.offerUpgrade()
    }
    MobileNavBar {
        id: mobileNav
        visible: home.mobile
        inlinePages: home.inlinePages
        onNewRequested: home.commands.newDevice()
        onSettingsRequested: home.commands.openSettings()
    }

    StackLayout {
        anchors.fill: parent
        currentIndex: home.page

        DevicesScreen {
            id: devicesScreen
            commands: home.commands
            busy: home.busy
            bundleUpdates: home.bundleUpdates
            cerfStatus: home.cerfStatus
            cerfAvailable: home.cerfAvailable
        }
        Loader {
            id: wizard
            active: home.inlinePages
            sourceComponent: NewDeviceWizard {
                flows: home.flows
                mobile: true
                onFinished: {
                    mobileNav.show(mobileNav.devicesPage)
                    restart()
                }
            }
        }
        Loader {
            id: settingsTab
            active: home.inlinePages
            sourceComponent: SettingsView {
                mobile: true
                rootBack: false
            }
        }
    }
}
