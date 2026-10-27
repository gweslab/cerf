import QtQuick
import QtQuick.Controls.Material as M

M.ScrollBar {
    interactive: !Theme.touchPlatform
}
