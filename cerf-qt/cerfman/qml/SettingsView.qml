import QtQuick
import QtQuick.Controls

SheetView {
    id: view
    property string initialPage: SheetIds.settingsEmulatorPage
    property string deviceLine: ""
    signal closed()

    function accept() {
        settings.accept(() => {
            if (view.split)
                view.closed()
            else
                view.goBack()
        })
    }

    title: qsTr("Settings")
    pages: [{"key": SheetIds.settingsEmulatorPage, "title": qsTr("Emulator Settings")},
            {"key": SheetIds.settingsFeedbackPage, "title": FeedbackModel.title},
            {"key": SheetIds.settingsAboutPage, "title": qsTr("About")}]
    pageKeys: pages.map(page => page.key)
    actionVisible: current === SheetIds.settingsEmulatorPage && (split || !menuShown)
    actionName: qsTr("OK")

    onAction: accept()
    onLeave: closed()

    Component.onCompleted: {
        current = initialPage
        if (!mobile)
            menuShown = false
    }

    footer: Loader {
        active: !view.mobile
        sourceComponent: SheetFooter {
            onAccept: view.accept()
            onReject: view.closed()
        }
    }

    GlobalSettingsPage {
        id: settings
    }
    FeedbackContent {
        compact: view.mobile
    }
    AboutContent {
        deviceLine: view.deviceLine
    }
}
