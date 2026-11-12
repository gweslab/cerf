import QtQuick
import QtQuick.Controls.Material
import QtQuick.Controls.Material as M

M.ApplicationWindow {
    color: Theme.pageBg
    Material.theme: Theme.dark ? Material.Dark : Material.Light
    Material.primary: Theme.barBg
    Material.accent: Theme.controlAccent
}
