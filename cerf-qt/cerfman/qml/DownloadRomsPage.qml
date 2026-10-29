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
    readonly property int sizeWidth: 90
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
        GridLayout {
            id: controls
            Layout.fillWidth: true
            columns: page.narrow ? 2 : 3
            columnSpacing: Theme.spaceM
            rowSpacing: Theme.spaceM

            UnsupportedSwitch {
                id: unsupported
                Layout.row: 0
                Layout.column: 0
                Layout.fillWidth: page.narrow
                onToggled: page.refill()
            }
            ComboBox {
                id: sort
                readonly property int byDownloads: 0
                readonly property int byName: 1
                Layout.row: page.narrow ? 1 : 0
                Layout.column: page.narrow ? 0 : 1
                Layout.columnSpan: page.narrow ? 2 : 1
                Layout.fillWidth: page.narrow
                implicitContentWidthPolicy: ComboBox.WidestText
                enabled: page.sortable
                model: [qsTr("Sort by downloads count"), qsTr("Sort by name")]
                onActivated: page.refill()
            }
            Button {
                Layout.row: 0
                Layout.column: page.narrow ? 1 : 2
                text: qsTr("Sources…")
                enabled: !BundleCatalog.loading
                onClicked: page.sources()
            }
        }
    ]
    footerLeading: [
        Button {
            text: RomDownloads.contactsTitle
            onClicked: page.flows.inform(RomDownloads.contactsTitle, RomDownloads.ContactsText(), page)
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
        const c = RomDownloads.Catalog(unsupported.checked, page.searchText,
                                       sort.currentIndex === sort.byDownloads)
        available = !c.noSources
        sortable = c.sortable
        if (!c.sortable)
            sort.currentIndex = sort.byName
        const flat = []
        c.groups.forEach(g => {
            flat.push({"kind": "group", "text": g.label, "soc": g.soc, "arches": g.arches,
                       "members": g.rows.map(r => r.key)})
            g.rows.forEach(r => {
                flat.push({"kind": "device", "key": r.key, "text": r.os, "size": r.size, "notes": r.notes})
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
            text: HtmlText.Link(page.repositoriesUrl, qsTr("What are bundle repositories?"))
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
                        GroupHeading {
                            narrow: page.narrow
                            text: slot.modelData.text
                            caption: slot.modelData.soc
                            arches: slot.modelData.arches
                        }
                    }
                }

                Component {
                    id: deviceRow
                    TableRow {
                        leftPadding: Theme.nestedIndent
                        onClicked: page.toggle(slot.modelData.key)

                        RowCheckBox {
                            checked: page.checked[slot.modelData.key] === true
                            onClicked: page.toggle(slot.modelData.key)
                        }
                        FoldedCell {
                            folded: true
                            text: slot.modelData.text
                            caption: slot.modelData.notes
                        }
                        SecondaryLabel {
                            Layout.preferredWidth: page.narrow ? -1 : page.sizeWidth
                            text: slot.modelData.size
                            horizontalAlignment: Text.AlignRight
                        }
                    }
                }
            }
        }
    }
}
