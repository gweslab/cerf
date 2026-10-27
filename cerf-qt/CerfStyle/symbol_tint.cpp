#include "symbol_tint.h"

#include "../qt_resource_paths.h"

QString SymbolTint::Url(const QUrl& symbol, const QColor& color) const { return TintedSymbolUrl(symbol, color); }
