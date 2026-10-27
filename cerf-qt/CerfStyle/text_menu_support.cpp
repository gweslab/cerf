#include "text_menu_support.h"

#include <QLibraryInfo>
#include <QVersionNumber>

bool TextMenuSupport::BuiltIn() const { return QLibraryInfo::version() >= QVersionNumber(6, 11); }
