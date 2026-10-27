import QtQuick
import QtQuick.Controls
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
    title: qsTr("%1 %2").arg(ProductLinks.productName).arg(AboutModel.version)

    function reload() {
        const reply = DeviceCards.Rows(home.query)
        const list = Array.from(reply.rows)
        cards = list
        const current = cards.find(r => r.name === selectedName)
        selectedRow = current !== undefined ? current : cards.length > 0 ? cards[0] : null
        selectedName = selectedRow !== null ? selectedRow.name : ""
        home.bundleUpdates = reply.bundleUpdates
        home.installed = reply.installed
        applyRows(list)
    }

    function refreshAll() {
        ++revision
        reload()
    }

    function applyRows(list) {
        const keys = new Set(list.map(r => r.key))
        for (let i = rows.count - 1; i >= 0; --i) {
            if (!keys.has(rows.get(i).key))
                rows.remove(i)
        }
        for (let i = 0; i < list.length; ++i) {
            if (i < rows.count && rows.get(i).key === list[i].key) {
                rows.set(i, list[i])
                continue
            }
            let found = -1
            for (let k = i + 1; k < rows.count; ++k) {
                if (rows.get(k).key === list[i].key) {
                    found = k
                    break
                }
            }
            if (found >= 0) {
                rows.move(found, i, 1)
                rows.set(i, list[i])
            } else {
                rows.insert(i, list[i])
            }
        }
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
            newDeviceWindow.createObject(window, {"flows": flows, "transientParent": window}).show()
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

    function launch(name, boot, confirmed) {
        if (ManagerOperations.RefuseWhileBusy())
            return
        const reply = DeviceActions.Launch(name, boot, confirmed === true)
        if (reply.confirm !== undefined) {
            flows.ask(reply.confirm.title, reply.confirm.message, () => launch(name, boot, true))
            return
        }
        if (flows.failed(reply))
            return
        if (reply.status !== undefined)
            flash(reply.status)
        reload()
    }

    function remove(name) {
        if (ManagerOperations.RefuseWhileBusy())
            return
        flows.ask(qsTr("Delete device"),
                  qsTr("Remove %1/ and its files?\nThis cannot be undone.").arg(DeviceActions.RelativePath(name)),
                  () => flows.failed(DeviceActions.Remove(name)))
    }

    function discard(name) {
        if (ManagerOperations.RefuseWhileBusy())
            return
        flows.ask(qsTr("Delete saved state"),
                  qsTr("Delete the saved state for %1?\nThis cannot be undone.").arg(selectedRow.deviceName),
                  () => {
            flows.failed(DeviceActions.DiscardSavedState(name))
            refreshAll()
        })
    }

    function updateDevice(name) {
        if (ManagerOperations.RefuseWhileBusy() || BundleCatalog.RefuseWhileLoading())
            return
        flows.updateDevice(name, host())
    }

    function updateAll() {
        if (ManagerOperations.RefuseWhileBusy() || BundleCatalog.RefuseWhileLoading())
            return
        flows.updateAll(host())
    }

    function offerUpgrade() {
        flows.offerUpgrade(host())
    }

    function packageAction(name, pkg) {
        if (pkg.installs)
            flows.installPackage(name, pkg, host())
        else
            flows.deletePackage(name, pkg, host())
    }

    function rename(name) {
        flows.prompt(host(), qsTr("Rename device"), qsTr("Display name (leave empty to reset):"), Qt.ImhNone,
                     text => {
            const error = DeviceActions.Rename(name, text)
            if (error !== "")
                flows.inform(qsTr("Rename failed"), error)
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
        flows.inform(qsTr("Saved state present"),
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

    ListModel {
        id: rows
    }

    ManagerFlows {
        id: flows
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
            flows.inform(title, text)
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
            flows.inform(title, text)
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
            flows.inform(qsTr("Upgrade complete"),
                         qsTr("%1 has been upgraded to %2.").arg(ProductLinks.productName).arg(AboutModel.version))
    }

    StackView {
        id: stack
        anchors.fill: parent
        focus: true
        initialItem: HomePage {
            id: home
            flows: flows
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
            flows: flows
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
