import QtQuick
import CerfStyle

SheetView {
    id: view
    property string deviceLine: ""
    signal closed()

    function accept() {
        if (enterprise.active && !enterprise.item.accept())
            return
        settings.accept(() => {
            if (view.split)
                view.closed()
            else
                view.goBack()
        })
    }

    function showPage(key) {
        show(key === SheetIds.settingsHomePage ? pages[0].key : key)
    }

    readonly property var allPages: [{"key": SheetIds.settingsEnterprisePage, "title": qsTr("Enterprise")},
                                     {"key": SheetIds.settingsEmulatorPage, "title": qsTr("Emulator Settings")},
                                     {"key": SheetIds.settingsTutorialPage, "title": qsTr("Tutorial")},
                                     {"key": SheetIds.settingsFeedbackPage, "title": FeedbackModel.title},
                                     {"key": SheetIds.settingsAboutPage, "title": qsTr("About")}]
    readonly property var hiddenPages: [EnterpriseModel.Allowed() ? "" : SheetIds.settingsEnterprisePage,
                                        FeedbackModel.available ? "" : SheetIds.settingsFeedbackPage]
    readonly property var savingPages: [SheetIds.settingsEnterprisePage, SheetIds.settingsEmulatorPage]

    title: qsTr("Settings")
    pages: allPages.filter(page => hiddenPages.indexOf(page.key) < 0)
    pageKeys: allPages.map(page => page.key)
    launchKeys: view.mobile ? [] : [SheetIds.settingsTutorialPage]
    actionVisible: savingPages.indexOf(current) >= 0 && (split || !menuShown)
    actionName: qsTr("OK")

    onAction: accept()
    onLeave: closed()
    onLaunched: Dialogs.openTutorial(view.Window.window)

    Component.onCompleted: {
        current = pages[0].key
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

    Loader {
        id: enterprise
        active: view.hiddenPages.indexOf(SheetIds.settingsEnterprisePage) < 0
        sourceComponent: EnterpriseSettingsPage {}
    }
    GlobalSettingsPage {
        id: settings
    }
    Loader {
        active: view.mobile
        sourceComponent: TutorialView {
            onFinished: {
                if (view.split)
                    view.show(SheetIds.settingsEmulatorPage)
                else
                    view.goBack()
            }
        }
    }
    FeedbackContent {
        compact: view.mobile
    }
    AboutContent {
        deviceLine: view.deviceLine
    }
}
