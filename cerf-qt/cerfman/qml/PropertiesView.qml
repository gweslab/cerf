import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

Page {
    id: view
    required property QtObject sheet
    property bool mobile: false
    property bool split: !mobile
    readonly property bool editable: sheet.editable
    readonly property bool live: sheet.live
    readonly property var pageKeys: [SheetIds.boardPage, SheetIds.guestAdditionsPage, SheetIds.displayPage,
                                     SheetIds.cpuConfigPage, SheetIds.emulatorPage]
    signal done()

    function accept() {
        if (!cpuPage.commitAll())
            return
        const problem = sheet.Problem()
        if (problem.title !== undefined) {
            sheetView.show(problem.page)
            Dialogs.inform(view, problem.title, problem.message)
            return
        }
        if (live && !sheet.forceReboot && sheet.rebootRequired) {
            const dialog = resetQuestion.createObject(view, {"choices": sheet.resetChoices,
                                                             "choice": sheet.softReset})
            dialog.chosen.connect(choice => view.save(choice))
            dialog.open()
            return
        }
        save(live && sheet.forceReboot ? sheet.softReset : sheet.noReset)
    }

    function save(reboot) {
        const error = sheet.Save()
        if (error !== "") {
            Dialogs.inform(view, live ? qsTr("Guest Additions") : qsTr("Properties"), qsTr("Could not save:\n%1").arg(error))
            return
        }
        sheet.Finish(reboot)
        done()
    }

    function reject() {
        sheet.Cancel()
        done()
    }

    function goBack() {
        if (stack.depth > 1) {
            stack.pop()
            return true
        }
        return sheetView.goBack()
    }

    function pickBoard(currentBoard) {
        stack.push(boardPicker, {"current": currentBoard, "mobile": view.mobile})
    }

    function bppHelp() {
        Dialogs.inform(view, qsTr("Color depth"), PropertyOptions.BppHelpText())
    }

    Component.onCompleted: {
        sheetView.current = sheet.initialPage
        sheetView.menuShown = mobile && sheet.initialPage === SheetIds.boardPage
    }

    Component {
        id: resetQuestion
        ResetQuestionDialog {}
    }

    Component {
        id: boardPicker
        BoardPickerPage {
            onPicked: boardId => {
                boardPage.setBoard(boardId)
                stack.pop()
            }
            onBack: stack.pop()
            onCancel: view.reject()
        }
    }

    StackView {
        id: stack
        anchors.fill: parent

        initialItem: SheetView {
            id: sheetView
            mobile: view.mobile
            split: view.split
            title: view.sheet.title
            pages: view.sheet.pages
            pageKeys: view.pageKeys
            actionVisible: !view.sheet.locked
            actionName: qsTr("OK")
            onAction: view.accept()
            onLeave: view.reject()

            footer: Loader {
                active: !view.mobile
                sourceComponent: SheetFooter {
                    acceptEnabled: !view.sheet.locked
                    warning: view.sheet.rebootRequired ? qsTr("Reboot required") : ""
                    onAccept: view.accept()
                    onReject: view.reject()
                    leading: Button {
                        text: qsTr("Open device directory")
                        onClicked: Dialogs.openDirectory(view, view.sheet.deviceDirectory)
                    }
                }
            }

            ScrollPage {
                BoardSettingsPage {
                    id: boardPage
                    Layout.fillWidth: true
                    sheet: view.sheet
                    editable: view.editable
                    onPickBoard: currentBoard => view.pickBoard(currentBoard)
                }
            }
            ScrollPage {
                GuestAdditionsPage {
                    Layout.fillWidth: true
                    sheet: view.sheet
                    editable: !view.sheet.locked
                    toggleLocked: view.live
                    onBppHelp: view.bppHelp()
                }
            }
            ScrollPage {
                DisplayPage {
                    Layout.fillWidth: true
                    sheet: view.sheet
                    editable: view.editable
                    onBppHelp: view.bppHelp()
                }
            }
            ScrollPage {
                CpuConfigPage {
                    id: cpuPage
                    Layout.fillWidth: true
                    sheet: view.sheet
                    editable: view.editable
                    onInvalidValue: message => Dialogs.inform(view, qsTr("Invalid value"), message)
                }
            }
            ScrollPage {
                EmulatorSettingsPage {
                    Layout.fillWidth: true
                    sheet: view.sheet
                    editable: view.editable
                }
            }
        }
    }
}
