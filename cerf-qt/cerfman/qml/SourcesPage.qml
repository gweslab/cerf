import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

WizardPage {
    id: page
    required property QtObject flows
    property var repos: []
    property int selected: -1
    readonly property int enabledWidth: 40
    readonly property int statusWidth: 90
    signal applied()

    actionName: qsTr("OK")

    function load() {
        repos = SourceRepositories.List().map(x => ({"url": x.url, "enabled": x.enabled,
                                                    "status": SourceRepositories.checking}))
        repos.forEach(x => SourceRepositories.Probe(x.url))
    }

    function setRepo(index, change) {
        const list = repos.slice()
        list[index] = Object.assign({}, list[index], change)
        repos = list
    }

    function add() {
        flows.prompt(page, SourceRepositories.addTitle, SourceRepositories.addPrompt,
                     Qt.ImhUrlCharactersOnly | Qt.ImhNoAutoUppercase, text => {
            if (text === "")
                return
            if (flows.failed(SourceRepositories.Check(text, repos.map(x => x.url)), page))
                return
            repos = repos.concat([{"url": text, "enabled": true, "status": SourceRepositories.checking}])
            SourceRepositories.Probe(text)
        })
    }

    function removeSelected() {
        repos = repos.filter((x, i) => i !== selected)
        selected = -1
    }

    function apply() {
        const error = SourceRepositories.Apply(repos.map(x => ({"url": x.url, "enabled": x.enabled})))
        if (error !== "") {
            flows.inform(SourceRepositories.title, qsTr("Could not save:\n%1").arg(error), page)
            return
        }
        applied()
    }

    title: SourceRepositories.title

    Component.onCompleted: load()

    Connections {
        target: SourceRepositories
        function onProbed(url, status) {
            const index = page.repos.findIndex(x => x.url === url)
            if (index >= 0)
                page.setRepo(index, {"status": status})
        }
    }

    onAction: page.apply()

    TableList {
        anchors.fill: parent
        headerVisible: !page.narrow
        columns: [
            ColumnTitle {
                Layout.preferredWidth: page.enabledWidth
                text: qsTr("On")
            },
            ColumnTitle {
                Layout.fillWidth: true
                text: qsTr("Repository URL")
            },
            ColumnTitle {
                Layout.preferredWidth: page.statusWidth
                text: qsTr("Status")
            }
        ]

        TableListView {
            model: page.repos

            delegate: TableRow {
                id: row
                required property var modelData
                required property int index
                width: ListView.view.width
                highlighted: row.index === page.selected
                onClicked: page.selected = row.index

                RowCheckBox {
                    Layout.preferredWidth: page.enabledWidth
                    checked: row.modelData.enabled
                    onClicked: page.setRepo(row.index, {"enabled": !row.modelData.enabled})
                }
                FoldedCell {
                    narrow: page.narrow
                    text: row.modelData.url
                    wrapMode: Text.WrapAnywhere
                    caption: row.modelData.status
                }
                SecondaryLabel {
                    Layout.preferredWidth: page.statusWidth
                    visible: !page.narrow
                    text: row.modelData.status
                }
            }
        }

        RowLayout {
            Layout.margins: Theme.spaceXL
            spacing: Theme.spaceS

            Button {
                text: qsTr("Add…")
                onClicked: page.add()
            }
            Button {
                text: qsTr("Delete")
                enabled: page.selected >= 0
                onClicked: page.removeSelected()
            }
        }
    }
}
