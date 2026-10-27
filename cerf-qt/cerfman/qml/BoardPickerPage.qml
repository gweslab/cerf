import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

WizardPage {
    id: page
    property string current: ""
    property string selected: current
    property var rows: []
    readonly property int socWidth: 180
    readonly property int supportWidth: 160
    signal picked(string boardId)

    title: qsTr("Pick a board")
    actionName: qsTr("OK")
    actionEnabled: selected !== ""
    searchable: true
    onAction: page.picked(page.selected)
    onSearchTextChanged: page.refill()
    filters: [
        Switch {
            id: hideUnknown
            text: qsTr("Hide unknown support")
            onToggled: page.refill()
        },
        HideUnsupportedSwitch {
            id: hideUnsupported
            onToggled: page.refill()
        }
    ]

    function refill() {
        const flat = []
        BoardCatalog.GroupedBoards(hideUnknown.checked, hideUnsupported.checked, page.searchText).forEach(g => {
            flat.push({"header": g.family, "id": "", "name": "", "soc": "", "support": ""})
            g.boards.forEach(b => flat.push({"header": "", "id": b.id, "name": b.name,
                                             "soc": b.soc, "support": b.support}))
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
                StrongLabel {
                    text: slot.modelData.header
                    leftPadding: Theme.spaceL
                    topPadding: Theme.spaceL
                    bottomPadding: Theme.spaceXS
                }
            }

            Component {
                id: boardRow
                RowDelegate {
                    columns: Theme.rowColumns(width, 3)
                    highlighted: slot.modelData.id === page.selected
                    onClicked: page.selected = slot.modelData.id
                    onDoubleClicked: page.picked(slot.modelData.id)

                    Label {
                        Layout.fillWidth: true
                        text: slot.modelData.name
                        wrapMode: Text.Wrap
                    }
                    CaptionLabel {
                        Layout.preferredWidth: page.socWidth
                        text: slot.modelData.soc
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
