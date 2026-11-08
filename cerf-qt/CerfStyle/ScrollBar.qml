import QtQuick
import QtQuick.Controls.Material as M

M.ScrollBar {
    interactive: Theme.scrollBarInteractive(size)
    hoverEnabled: interactive
}
