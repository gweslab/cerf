import QtQuick
import QtQuick.Controls
import CerfStyle

Page {
    id: page
    readonly property bool narrow: width < Theme.narrowTableWidth
    property bool mobile: false
    property string actionName: ""
    property bool actionEnabled: true
    property bool searchable: false
    property bool footerOnMobile: false
    property alias filters: top.filters
    property alias footerLeading: bottom.leading
    property alias footerStacked: bottom.stacked
    readonly property alias searchText: top.searchText
    signal back()
    signal action()
    signal cancel()

    header: page.mobile || page.searchable ? top : null
    footer: !page.mobile || page.footerOnMobile ? bottom : null

    SearchPageHeader {
        id: top
        visible: page.mobile || page.searchable
        mobile: page.mobile
        searchable: page.searchable
        title: page.title
        actionName: page.actionName
        actionEnabled: page.actionEnabled
        onBack: page.back()
        onAction: page.action()
    }
    WizardFooter {
        id: bottom
        visible: !page.mobile || page.footerOnMobile
        mobile: page.mobile
        actionName: page.actionName
        actionEnabled: page.actionEnabled
        onBack: page.back()
        onAction: page.action()
        onCancel: page.cancel()
    }
}
