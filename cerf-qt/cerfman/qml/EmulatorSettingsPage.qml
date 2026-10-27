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
