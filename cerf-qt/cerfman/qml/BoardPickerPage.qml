import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

WizardPage {
    id: page
    property string current: ""
    property string selected: current
    property var rows: []
    readonly property int supportWidth: 160
    signal picked(string boardId)

    title: qsTr("Pick a board")
    actionName: qsTr("OK")
    actionEnabled: selected !== ""
    searchable: true
    onAction: page.picked(page.selected)
    onSearchTextChanged: page.refill()
    filters: [
        Flow {
            Layout.fillWidth: true
            spacing: Theme.spaceM

            UnsupportedSwitch {
                id: unsupported
                onToggled: page.refill()
            }
            Switch {
                id: unknown
                text: qsTr("Unknown support")
                checked: true
                onToggled: page.refill()
            }
        }
    ]

    function refill() {
        const flat = []
        BoardCatalog.GroupedBoards(unsupported.checked, unknown.checked, page.searchText).forEach(g => {
            flat.push({"header": g.family, "soc": g.soc, "arches": g.arches})
            g.boards.forEach(b => flat.push({"header": "", "id": b.id, "name": b.name, "support": b.support}))
        })
        rows = flat
    }

    Component.onCompleted: refill()

    TableListView {
        anchors.fill: parent
        model: page.rows

        delegate: Loader {
            id: slot
            required property var modelData
            width: ListView.view.width
            sourceComponent: slot.modelData.header !== "" ? familyRow : boardRow

            Component {
                id: familyRow
                GroupHeading {
                    leftPadding: Theme.spaceL
                    rightPadding: Theme.spaceL
                    topPadding: Theme.spaceL
                    bottomPadding: Theme.spaceXS
                    narrow: page.narrow
                    text: slot.modelData.header
                    caption: slot.modelData.soc
                    arches: slot.modelData.arches
                }
            }

            Component {
                id: boardRow
                RowDelegate {
                    columns: Theme.rowColumns(width, 2)
                    highlighted: slot.modelData.id === page.selected
                    onClicked: page.selected = slot.modelData.id
                    onDoubleClicked: page.picked(slot.modelData.id)

                    Label {
                        Layout.fillWidth: true
                        text: slot.modelData.name
                        wrapMode: Text.Wrap
                    }
                    CaptionLabel {
                        Layout.preferredWidth: page.supportWidth
                        text: slot.modelData.support
                    }
                }
            }
        }
    }
}
