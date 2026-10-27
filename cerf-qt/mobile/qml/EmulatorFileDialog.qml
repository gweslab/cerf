import QtQuick
import QtQuick.Dialogs

FileDialog {
    id: dialog
    property bool multiple: false
    signal finished(var chosen)

    fileMode: multiple ? FileDialog.OpenFiles : FileDialog.OpenFile

    onAccepted: {
        const chosen = []
        if (multiple) {
            for (let i = 0; i < selectedFiles.length; ++i)
                chosen.push(selectedFiles[i].toString())
        } else {
            chosen.push(selectedFile.toString())
        }
        finished(chosen)
        destroy()
    }
    onRejected: {
        finished([])
        destroy()
    }
}
