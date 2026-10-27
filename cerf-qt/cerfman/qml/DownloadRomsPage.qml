import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

WizardPage {
    id: page
    required property QtObject flows
    property var rows: []
    property var checked: ({})
    property bool available: true
    property bool sortable: false
    readonly property string repositoriesUrl: RomDownloads.repositoriesUrl
    readonly property int checkedCount: Object.keys(checked).length
    readonly property string summary: RomDownloads.Summary(Object.keys(checked))
    readonly property int socWidth: 150
    readonly property int sizeWidth: 90
    readonly property int noteIconSize: 16
    signal started()
    signal sources()

    title: qsTr("Download ROMs")
    actionName: qsTr("Download")
    actionEnabled: checkedCount > 0 && !ManagerOperations.busy
    searchable: true
    footerOnMobile: true
    footerStacked: page.narrow
    onAction: page.start()
    onSearchTextChanged: page.refill()
    filters: [
        HideUnsupportedSwitch {
            id: hideUnsupported
            onToggled: page.refill()
        },
        Row {
            spacing: Theme.spaceXS

            Label {
                anchors.verticalCenter: parent.verticalCenter
                text: qsTr("Sort:")
            }
            ComboBox {
                id: sort
                readonly property int byDownloads: 0
                readonly property int regular: 1
                implicitContentWidthPolicy: ComboBox.WidestText
                enabled: page.sortable
                model: [qsTr("By downloads"), qsTr("Regular")]
                onActivated: page.refill()
            }
        },
        Button {
            text: qsTr("Sources…")
            enabled: !BundleCatalog.loading
            onClicked: page.sources()
        }
    ]
    footerLeading: [
        Button {
            text: RomDownloads.copyrightRemovalTitle
            onClicked: page.flows.inform(RomDownloads.copyrightRemovalTitle, RomDownloads.CopyrightText(), page)
        },
        Label {
            text: page.summary
        }
    ]

    function groupState(map, members) {
        const count = members.filter(key => map[key] === true).length
        return count === 0 ? Qt.Unchecked : count === members.length ? Qt.Checked
                                                                     : Qt.PartiallyChecked
    }

    function setChecked(keys, on) {
        const next = Object.assign({}, checked)
        keys.forEach(key => {
            if (on)
                next[key] = true
            else
                delete next[key]
        })
        checked = next
    }

    function toggle(key) {
        setChecked([key], checked[key] !== true)
    }

    function toggleGroup(members) {
        setChecked(members, groupState(checked, members) !== Qt.Checked)
    }

    function start() {
        flows.download(Object.keys(checked), () => page.started())
    }

    function refill() {
        const c = RomDownloads.Catalog(hideUnsupported.checked, page.searchText,
                                       sort.currentIndex === sort.byDownloads)
        available = !c.noSources
        sortable = c.sortable
        if (!c.sortable)
            sort.currentIndex = sort.regular
        const flat = []
        c.groups.forEach(g => {
            flat.push({"kind": "group", "text": g.label,
                       "members": g.rows.map(r => r.key)})
            g.rows.forEach(r => {
                flat.push({"kind": "device", "key": r.key, "text": r.os, "soc": r.soc,
                           "size": r.size, "detail": r.detail, "notes": r.notes})
            })
        })
        rows = flat
    }

    Component.onCompleted: refill()
    StackView.onActivated: refill()

    Connections {
        target: BundleCatalog
        function onRefreshed() {
            page.refill()
        }
    }

    ColumnLayout {
        anchors.centerIn: parent
        visible: !page.available
        spacing: Theme.spaceM

        Label {
            Layout.alignment: Qt.AlignHCenter
            text: qsTr("No bundle repositories available.")
        }
        LinkLabel {
            Layout.alignment: Qt.AlignHCenter
            wrapMode: Text.NoWrap
            text: HtmlText.Link(page.repositoriesUrl, qsTr("See how to find a bundle repository"))
        }
    }

    TableList {
        anchors.fill: parent
        visible: page.available
        headerVisible: !page.narrow
        columns: [
            ColumnTitle {
                Layout.fillWidth: true
                text: qsTr("Device / OS")
            },
            ColumnTitle {
                Layout.preferredWidth: page.socWidth
                text: qsTr("SoC")
            },
            ColumnTitle {
                Layout.preferredWidth: page.sizeWidth
                text: qsTr("Size")
                horizontalAlignment: Text.AlignRight
            }
        ]

        TableListView {
            model: page.rows

            delegate: Loader {
                id: slot
                required property var modelData
                width: ListView.view.width
                sourceComponent: slot.modelData.kind === "group" ? groupRow : deviceRow

                Component {
                    id: groupRow
                    TableRow {
                        onClicked: page.toggleGroup(slot.modelData.members)

                        RowCheckBox {
                            tristate: true
                            checkState: page.groupState(page.checked, slot.modelData.members)
                            onClicked: page.toggleGroup(slot.modelData.members)
                        }
                        StrongLabel {
                            Layout.fillWidth: true
                            text: slot.modelData.text
                            wrapMode: Text.Wrap
                        }
                    }
                }

                Component {
                    id: deviceRow
                    TableRow {
                        leftPadding: Theme.nestedIndent
                        columns: 4
                        onClicked: page.toggle(slot.modelData.key)

                        RowCheckBox {
                            Layout.row: 0
                            Layout.column: 0
                            checked: page.checked[slot.modelData.key] === true
                            onClicked: page.toggle(slot.modelData.key)
                        }
                        FoldedCell {
                            Layout.row: 0
                            Layout.column: 1
                            narrow: page.narrow
                            text: slot.modelData.text
                            caption: slot.modelData.detail
                        }
                        SecondaryLabel {
                            Layout.row: 0
                            Layout.column: 2
                            Layout.preferredWidth: page.socWidth
                            visible: !page.narrow
                            text: slot.modelData.soc
                        }
                        SecondaryLabel {
                            Layout.row: 0
                            Layout.column: 3
                            Layout.preferredWidth: page.sizeWidth
                            visible: !page.narrow
                            text: slot.modelData.size
                            horizontalAlignment: Text.AlignRight
                        }
                        Repeater {
                            model: slot.modelData.notes

                            RowLayout {
                                id: noteLine
                                required property int index
                                required property string modelData
                                Layout.row: index + 1
                                Layout.column: 1
                                Layout.columnSpan: 3
                                Layout.fillWidth: true
                                Layout.bottomMargin: Theme.spaceS
                                spacing: Theme.spaceXS

                                SymbolIcon {
                                    Layout.alignment: Qt.AlignTop
                                    name: "subdirectory_arrow_right"
                                    size: page.noteIconSize
                                    color: Theme.dim
                                }
                                SecondaryLabel {
                                    Layout.fillWidth: true
                                    text: noteLine.modelData
                                    wrapMode: Text.Wrap
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
