#include "global_menu_bar.h"

#include <QWindow>

struct GlobalMenuBar::Native {};

GlobalMenuBar::GlobalMenuBar(QWindow& window, MenuSource&) : QObject(&window) {}

GlobalMenuBar::~GlobalMenuBar() = default;
