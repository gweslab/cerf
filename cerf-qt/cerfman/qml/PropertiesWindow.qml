import QtQuick
import CerfStyle

PageWindow {
    id: host
    required property QtObject sheet
    property bool mobile: false
    property bool finished: false

    function goBack() {
        return view.goBack()
    }

    title: sheet.title
    width: 900
    height: 680
    minimumWidth: mobile ? 0 : Theme.sheetWindowMinimumWidth
    minimumHeight: mobile ? 0 : Theme.sheetWindowMinimumHeight

    onClosing: if (!finished) sheet.Cancel()

    PropertiesView {
        id: view
        anchors.fill: parent
        focus: true
        sheet: host.sheet
        mobile: host.mobile
        split: !host.mobile || host.width >= Theme.compactWidth
        onDone: {
            host.finished = true
            host.close()
        }
    }
}
