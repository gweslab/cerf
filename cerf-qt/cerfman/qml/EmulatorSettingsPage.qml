import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import CerfStyle

SheetPage {
    id: page

    SettingsGroup {
        SettingsNote {
            divider: false
            text: qsTr("Changing this setting will render emulation broken. Expect crashes or wrong behaviour.")
        }
        SettingsRow {
            title: qsTr("Throttle multiplier")
            description: qsTr("Set how fast the guest runs: 2 is half speed, and 0 is as fast as the host allows.")
            MultiplierBox {
                enabled: page.editable
                sheet: page.sheet
                key: SheetIds.throttleMultiplier
            }
        }
    }

    SettingsGroup {
        SettingsRow {
            title: qsTr("HUD")
            description: qsTr("On-screen device buttons around the screen.")
            ChoiceBox {
                enabled: page.editable || page.sheet.live
                values: PropertyOptions.HudChoices()
                current: page.sheet.hud
                labelOf: v => PropertyOptions.HudLabel(v, page.sheet.boardId)
                onPicked: value => page.sheet.SetOrClear(SheetIds.hud, value)
            }
        }
    }

    SettingsGroup {
        SwitchRow {
            visible: page.sheet.fullScreenSetting
            title: qsTr("Borderless full screen")
            divider: false
            editable: page.editable
            checked: page.sheet.fullScreen
            onToggled: page.sheet.SetValue(SheetIds.fullScreen, checked)
        }
        SwitchRow {
            title: qsTr("Detach internet connection")
            divider: page.sheet.fullScreenSetting
            editable: page.editable
            checked: !page.sheet.networkEnabled
            onToggled: page.sheet.SetValue(SheetIds.networkEnabled, !checked)
        }
        SwitchRow {
            visible: page.sheet.doubleTapHelperSetting
            title: qsTr("Double-tap helper")
            description: qsTr("Emulator will detect double taps and send second exactly at the position of first to prevent a drift")
            editable: page.editable
            checked: page.sheet.doubleTapHelper
            onToggled: page.sheet.SetValue(SheetIds.doubleTapHelper, checked)
        }
    }
}
