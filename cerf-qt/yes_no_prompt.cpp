#include "yes_no_prompt.h"

#include "nested_event_loops.h"
#include "qt_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QString>
#include <QVariantList>
#include <QVariantMap>

namespace cerffrontend {

REGISTER_SERVICE(YesNoPrompt);

PromptAnswer YesNoPrompt::Ask(const std::string& title, const std::string& message, YesNoLevel level,
                              YesNoEnter enter, const std::function<void(QObject*)>& opened) {
    const QString yes = QStringLiteral("Yes");
    const QString no  = QStringLiteral("No");
    QVariantMap   properties{{QStringLiteral("title"), QString::fromStdString(title)},
                           {QStringLiteral("message"), QString::fromStdString(message)},
                           {QStringLiteral("buttons"), QVariantList{yes, no}},
                           {QStringLiteral("enterChoice"), enter == YesNoEnter::kYes ? yes : no}};
    if (level == YesNoLevel::kWarning) properties.insert(QStringLiteral("level"), QStringLiteral("warning"));
    const QVariant choice = emu_.Get<QtEmulatorWindow>().RunDialog(QStringLiteral("FlowDialog"), properties, opened);
    if (emu_.Get<NestedEventLoops>().Quitting()) return PromptAnswer::kClosed;
    return choice.toString() == yes ? PromptAnswer::kYes : PromptAnswer::kNo;
}

}
