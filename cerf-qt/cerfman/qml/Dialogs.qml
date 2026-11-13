pragma Singleton
import QtQuick

QtObject {
    readonly property Component flowDialog: Component {
        FlowDialog {}
    }
    readonly property Component settingsWindow: Component {
        SettingsWindow {}
    }
    readonly property Component tutorialWindow: Component {
        TutorialWindow {}
    }

    function show(host, props, done) {
        const dialog = flowDialog.createObject(host, props)
        if (done)
            dialog.choice.connect(done)
        dialog.open()
    }

    function inform(host, title, message, done) {
        show(host, {"title": title, "message": message}, done)
    }

    function question(host, props, buttons, done) {
        const dialog = Object.assign({}, props)
        dialog.buttons = buttons
        show(host, dialog, done)
    }

    function ask(host, props, onYes) {
        const yes = qsTr("Yes")
        question(host, props, [yes, qsTr("No")], choice => { if (choice === yes) onYes() })
    }

    function choose(host, props, options, done) {
        question(host, props, options.concat([qsTr("Cancel")]), done)
    }

    function retry(host, title, message, answer) {
        const again = qsTr("Retry")
        choose(host, {"title": title, "message": message}, [again], choice => answer(choice === again))
    }

    function openDirectory(host, path) {
        const error = DesktopShell.OpenPath(path)
        if (error !== "")
            inform(host, qsTr("Open device directory"), error)
    }

    function openWindow(key, component, owner, props) {
        const shown = WindowRegistry.Raise(key)
        if (shown !== null)
            return shown
        const window = component.createObject(owner, props)
        WindowRegistry.Track(key, window)
        window.show()
        return window
    }

    function openSettings(parentWindow, initialPage, deviceLine) {
        const props = {"transientParent": parentWindow}
        if (deviceLine !== undefined)
            props.deviceLine = deviceLine
        const window = openWindow("SettingsWindow", settingsWindow, parentWindow, props)
        if (initialPage !== undefined)
            window.showPage(initialPage)
    }

    function openTutorial(parentWindow, done) {
        const window = openWindow("TutorialWindow", tutorialWindow, parentWindow, {"transientParent": parentWindow})
        if (done)
            window.finished.connect(done)
    }
}
