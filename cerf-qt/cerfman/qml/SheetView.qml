import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

Page {
    id: sheet
    property bool mobile: false
    property bool split: !mobile
    property var pages: []
    property var pageKeys: []
    property string current: ""
    property bool menuShown: mobile
    property bool rootBack: true
    property bool actionVisible: false
    property string actionName: ""
    property var launchKeys: []
    readonly property int menuWidth: 200
    readonly property string currentTitle: {
        const page = pages.find(p => p.key === current)
        return page !== undefined ? page.title : ""
    }
    default property alias pageItems: stack.data
    signal action()
    signal leave()
    signal launched(string key)

    function pick(key) {
        if (launchKeys.indexOf(key) >= 0)
            launched(key)
        else
            show(key)
    }

    function show(key) {
        current = key
        menuShown = false
    }

    function goBack() {
        if (!split && !menuShown) {
            menuShown = true
            return true
        }
        if (!rootBack)
            return false
        leave()
        return true
    }

    onPagesChanged: if (!pages.some(p => p.key === current)) current = pages[0].key

    header: sheet.mobile ? bar : null

    PageBar {
        id: bar
        visible: sheet.mobile
        title: sheet.split || sheet.menuShown ? sheet.title : sheet.currentTitle
        backVisible: sheet.rootBack || (!sheet.split && !sheet.menuShown)
        actionVisible: sheet.actionVisible
        actionName: sheet.actionName
        onBack: sheet.goBack()
        onAction: sheet.action()
    }

    RowLayout {
        anchors.fill: parent
        spacing: 0

        ListView {
            Layout.fillHeight: true
            Layout.fillWidth: !sheet.split
            Layout.preferredWidth: sheet.menuWidth
            visible: sheet.split || sheet.menuShown
            topMargin: Theme.spaceXXL
            model: sheet.pages
            delegate: ItemDelegate {
                required property var modelData
                width: ListView.view.width
                text: modelData.title
                highlighted: sheet.split && modelData.key === sheet.current
                onClicked: sheet.pick(modelData.key)
            }
        }
        Divider {
            Layout.fillHeight: true
            vertical: true
            visible: sheet.split
        }
        StackLayout {
            id: stack
            Layout.fillWidth: true
            Layout.fillHeight: true
            visible: sheet.split || !sheet.menuShown
            currentIndex: sheet.pageKeys.indexOf(sheet.current)
        }
    }
}
