import QtQuick
import QtQuick.Layouts
import CerfStyle

ApplicationWindow {
    id: window
    property bool upgraded: false

    readonly property bool mobile: width < Theme.compactWidth
    readonly property bool touchPlatform: Theme.touchPlatform
    readonly property bool busy: ManagerOperations.busy
    property string selectedName: ""
    property var selectedRow: null
    property var cards: []
    property int revision: 0
    property string flashText: ""
    property var warnedStates: ({})

    width: 1100
    height: 640
    minimumWidth: Theme.windowMinimumWidth
    minimumHeight: Theme.windowMinimumHeight
    visible: true
    title: qsTr("%1 Device Manager %2").arg(ProductLinks.productName).arg(AboutModel.displayVersion)

    function reload() {
        const reply = DeviceCards.Rows(home.query)
        const list = Array.from(reply.rows)
        cards = list
        const current = cards.find(r => r.name === selectedName)
        selectedRow = current !== undefined ? current : cards.length > 0 ? cards[0] : null
        selectedName = selectedRow !== null ? selectedRow.name : ""
        home.bundleUpdates = reply.bundleUpdates
        home.installed = reply.installed
        rows.apply(list)
    }

    function refreshAll() {
        ++revision
        reload()
    }

    function flash(text) {
        flashText = text
        if (text !== "")
            flashTimer.restart()
    }

    function host() {
        return window.contentItem
    }

    function newDevice() {
        if (ManagerOperations.RefuseWhileBusy())
            return
        if (touchPlatform && mobile)
            home.showNewTab()
        else if (touchPlatform)
            pushPage(newDevicePage)
        else
            newDeviceWindow.createObject(window, {"flows": managerFlows, "transientParent": window}).show()
    }

    function openSettings() {
        if (touchPlatform && mobile)
            home.showSettingsTab()
        else if (touchPlatform)
            pushPage(settingsPage)
        else
            Dialogs.openSettings(window)
    }

    function pushPage(component) {
        const item = stack.push(component)
        if (item.closed !== undefined)
            item.closed.connect(() => stack.pop())
    }

    function openTutorial(done) {
        if (!touchPlatform) {
            Dialogs.openTutorial(window, done)
            return
        }
        const page = stack.push(tutorialPage)
        page.finished.connect(() => {
            stack.pop()
            done()
        })
    }

    function launch(name, boot) {
        if (TutorialState.finished || DeviceActions.Running(name)) {
            startDevice(name, boot, false)
            return
        }
        if (!ManagerOperations.RefuseWhileBusy())
            openTutorial(() => startDevice(name, boot, false))
    }

    function startDevice(name, boot, confirmed) {
        if (ManagerOperations.RefuseWhileBusy())
            return
        const reply = DeviceActions.Launch(name, boot, confirmed)
        if (reply.confirm !== undefined) {
            managerFlows.ask(reply.confirm.title, reply.confirm.message, () => startDevice(name, boot, true))
            return
        }
        if (managerFlows.failed(reply))
            return
        if (reply.status !== undefined)
            flash(reply.status)
        reload()
    }

    function remove(name) {
        if (ManagerOperations.RefuseWhileBusy())
            return
        managerFlows.ask(qsTr("Delete device"),
                  qsTr("Remove %1/ and its files?\nThis cannot be undone.").arg(DeviceActions.RelativePath(name)),
                  () => managerFlows.failed(DeviceActions.Remove(name)))
    }

    function discard(name) {
        if (ManagerOperations.RefuseWhileBusy())
            return
        managerFlows.ask(qsTr("Delete saved state"),
                  qsTr("Delete the saved state for %1?\nThis cannot be undone.").arg(selectedRow.deviceName),
                  () => {
            managerFlows.failed(DeviceActions.DiscardSavedState(name))
            refreshAll()
        })
    }

    function updateDevice(name) {
        if (ManagerOperations.RefuseWhileBusy() || BundleCatalog.RefuseWhileLoading())
            return
        managerFlows.updateDevice(name, host())
    }

    function updateAll() {
        if (ManagerOperations.RefuseWhileBusy() || BundleCatalog.RefuseWhileLoading())
            return
        managerFlows.updateAll(host())
    }

    function offerUpgrade() {
        managerFlows.offerUpgrade(host())
    }

    function packageAction(name, pkg) {
        if (pkg.installs)
            managerFlows.installPackage(name, pkg, host())
        else
            managerFlows.deletePackage(name, pkg, host())
    }

    function rename(name) {
        managerFlows.prompt(host(), qsTr("Rename device"), qsTr("Display name (leave empty to reset):"), Qt.ImhNone,
                     text => {
            const error = DeviceActions.Rename(name, text)
            if (error !== "")
                managerFlows.inform(qsTr("Rename failed"), error)
        }, DeviceActions.DisplayName(name))
    }

    function openDirectory(name) {
        Dialogs.openDirectory(host(), DeviceActions.Directory(name))
    }

    function warnSavedState(name) {
        if (warnedStates[name] === true || !DeviceActions.HasSavedState(name))
            return
        const next = Object.assign({}, warnedStates)
        next[name] = true
        warnedStates = next
        managerFlows.inform(qsTr("Saved state present"),
                     qsTr("This device has a saved state.\n\nSome changes require soft/hard reset to be applied "
                          + "and some might damage your saved state image."))
    }

    function openProperties(name, page) {
        if (ManagerOperations.RefuseWhileBusy())
            return
        const sheet = PropertySheets.CreateForDevice(name, DeviceActions.Running(name), page)
        sheet.finished.connect(accepted => {
            if (!accepted)
                return
            warnSavedState(name)
            selectedName = name
            refreshAll()
        })
        if (touchPlatform) {
            const view = stack.push(propertiesPage, {"sheet": sheet})
            view.done.connect(() => stack.pop())
        } else {
            propertiesWindow.createObject(window, {"sheet": sheet, "transientParent": window}).show()
        }
    }

    function pick(name) {
        const found = cards.find(r => r.name === name)
        selectedRow = found !== undefined ? found : null
        selectedName = selectedRow !== null ? name : ""
        if (mobile && stack.depth === 1)
            stack.push(devicePage)
    }

    function contextMenu(name, item, at) {
        if (ManagerOperations.RefuseWhileBusy())
            return
        const row = cards.find(r => r.name === name)
        selectedRow = row
        selectedName = name
        cardMenu.row = row
        cardMenu.popup(item, at.x, at.y)
    }

    function goBack() {
        if (stack.depth > 1) {
            const item = stack.currentItem
            if (item.goBack === undefined || !item.goBack())
                stack.pop()
            return true
        }
        return home.goBack()
    }

    KeyedListModel {
        id: rows
    }

    ManagerFlows {
        id: managerFlows
        defaultHost: window.contentItem
    }

    Connections {
        target: ManagerOperations
        function onDevicesChanged() {
            window.refreshAll()
        }
        function onStatus(text) {
            window.flash(text)
        }
        function onMessage(title, text) {
            managerFlows.inform(title, text)
        }
        function onBusyChanged() {
            window.reload()
        }
    }

    Connections {
        target: BundleCatalog
        function onRefreshed() {
            window.refreshAll()
        }
        function onMessage(title, text) {
            managerFlows.inform(title, text)
        }
        function onStatus(text) {
            window.flash(text)
        }
        function onLoadingChanged() {
            window.reload()
        }
    }

    Connections {
        target: UserDeviceCreator
        function onCreated(name) {
            window.selectedName = name
            window.refreshAll()
        }
    }

    Connections {
        target: CerfUpdates
        function onOfferReady() {
            window.offerUpgrade()
        }
    }

    Connections {
        target: SettingsModel
        function onUpdateChannelChanged() {
            CerfUpdates.Check()
        }
    }

    Timer {
        interval: 2500
        repeat: true
        running: true
        onTriggered: window.reload()
    }

    Timer {
        id: flashTimer
        interval: 4000
    }

    Component.onCompleted: {
        WindowLifetime.DeleteWhenClosed(window)
        reload()
        BundleCatalog.Refresh(false)
        CerfUpdates.Check()
        if (upgraded)
            managerFlows.inform(qsTr("Upgrade complete"),
                         qsTr("%1 has been upgraded to %2.").arg(ProductLinks.productName).arg(AboutModel.version))
    }

    StackView {
        id: stack
        anchors.fill: parent
        focus: true
        initialItem: HomePage {
            id: home
            flows: managerFlows
            commands: window
            mobile: window.mobile
            inlinePages: window.touchPlatform
            model: rows
            listBottomInset: toast.visible ? toastLane.implicitHeight : 0
            compact: window.mobile
            busy: window.busy
            selectedName: window.selectedName
            selectedRow: window.selectedRow
            revision: window.revision
            cerfStatus: CerfUpdates.status
            cerfAvailable: CerfUpdates.available
            onQueryChanged: window.reload()
        }
    }

    ColumnLayout {
        id: toastLane
        anchors.left: parent.left
        anchors.right: parent.right
        anchors.bottom: parent.bottom
        anchors.bottomMargin: home.footer !== null ? home.footer.height : 0
        z: 1

        ProgressToast {
            id: toast
            Layout.fillWidth: true
            Layout.maximumWidth: preferredWidth
            Layout.alignment: Qt.AlignHCenter
            Layout.topMargin: Theme.spaceXL
            Layout.bottomMargin: Theme.spaceXL
            Layout.leftMargin: Theme.spaceXXXL
            Layout.rightMargin: Theme.spaceXXXL
            visible: window.busy || BundleCatalog.loading || flashTimer.running
            label: window.busy ? ManagerOperations.label
                               : BundleCatalog.loading ? BundleCatalog.loadingLabel : window.flashText
            spinning: (window.busy && !ManagerOperations.progressShown) || (!window.busy && BundleCatalog.loading)
            progress: window.busy && ManagerOperations.progressShown
            done: ManagerOperations.done
            total: ManagerOperations.total
        }
    }

    DeviceCardMenu {
        id: cardMenu
        onLaunchRequested: name => window.launch(name, "")
        onDiscardRequested: name => window.discard(name)
        onUpdateRequested: name => window.updateDevice(name)
        onOpenDirectoryRequested: name => window.openDirectory(name)
        onRemoveRequested: name => window.remove(name)
        onRenameRequested: name => window.rename(name)
        onPropertiesRequested: name => window.openProperties(name, SheetIds.boardPage)
    }

    Component {
        id: newDeviceWindow
        NewDeviceWindow {}
    }

    Component {
        id: tutorialPage
        TutorialView {}
    }

    Component {
        id: settingsPage
        SettingsView {
            mobile: true
            split: !window.mobile
        }
    }

    Component {
        id: propertiesWindow
        PropertiesWindow {}
    }

    Component {
        id: propertiesPage
        PropertiesView {
            mobile: true
            split: !window.mobile
        }
    }

    Component {
        id: newDevicePage
        NewDeviceWizard {
            flows: managerFlows
            mobile: true
            closable: true
            onFinished: stack.pop()
        }
    }

    Component {
        id: devicePage
        DevicePage {
            commands: window
            row: window.selectedRow
            busy: window.busy
            revision: window.revision
            onBack: stack.pop()
        }
    }

    onMobileChanged: if (!touchPlatform && !mobile && stack.depth > 1) stack.pop(null)
}
