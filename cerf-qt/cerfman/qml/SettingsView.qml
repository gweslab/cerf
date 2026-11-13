import QtQuick
import CerfStyle

SheetView {
    id: view
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

    readonly property var allPages: [{"key": SheetIds.settingsEmulatorPage, "title": qsTr("Emulator Settings")},
                                     {"key": SheetIds.settingsTutorialPage, "title": qsTr("Tutorial")},
                                     {"key": SheetIds.settingsFeedbackPage, "title": FeedbackModel.title},
                                     {"key": SheetIds.settingsAboutPage, "title": qsTr("About")}]

    title: qsTr("Settings")
    pages: allPages.filter(page => page.key !== SheetIds.settingsFeedbackPage || FeedbackModel.available)
    pageKeys: allPages.map(page => page.key)
    launchKeys: view.mobile ? [] : [SheetIds.settingsTutorialPage]
    actionVisible: current === SheetIds.settingsEmulatorPage && (split || !menuShown)
    actionName: qsTr("OK")

    onAction: accept()
    onLeave: closed()
    onLaunched: Dialogs.openTutorial(view.Window.window)

    Component.onCompleted: {
        current = SheetIds.settingsEmulatorPage
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
