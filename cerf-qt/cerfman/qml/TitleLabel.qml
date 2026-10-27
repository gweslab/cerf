import QtQuick
import QtQuick.Controls
import CerfStyle

Label {
    enum Level {
        Tile,
        Section,
        Bar,
        Headline,
        Display
    }

    property int level: TitleLabel.Section

    font.bold: true
    font.pixelSize: {
        switch (level) {
        case TitleLabel.Tile:
            return Theme.tileTitleSize
        case TitleLabel.Bar:
            return Theme.barTitleSize
        case TitleLabel.Headline:
            return Theme.headlineSize
        case TitleLabel.Display:
            return Theme.displaySize
        default:
            return Theme.sectionTitleSize
        }
    }
}
