pragma Singleton
import QtQuick

QtObject {
    readonly property Component flowDialog: Component {
        FlowDialog {}
    }
    readonly property Component settingsWindow: Component {
        SettingsWindow {}
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

    function openSettings(parentWindow, initialPage) {
        const props = {"transientParent": parentWindow}
        if (initialPage !== undefined)
            props.initialPage = initialPage
        settingsWindow.createObject(parentWindow, props).show()
    }
}
