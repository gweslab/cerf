qt_add_library(cerfqt_style STATIC)
set_source_files_properties(Theme.qml PROPERTIES QT_QML_SINGLETON_TYPE TRUE)
set(cerfqt_style_host_sources touch_frontend_default.cpp touch_frontend_android.cpp
    host_accent_windows.cpp host_accent_macos.mm host_accent_linux.cpp host_accent_android.cpp)
cerfcore_select_host_sources(cerfqt_style_host_sources)
qt_add_qml_module(cerfqt_style
    URI CerfStyle
    VERSION 1.0
    IMPORTS
        QtQuick.Controls.Material
    QML_FILES
        ApplicationWindow.qml
        Button.qml
        ComboBox.qml
        Dialog.qml
        FieldBackground.qml
        Menu.qml
        MenuBar.qml
        MenuBarItem.qml
        MenuItem.qml
        MenuSeparator.qml
        Page.qml
        ScrollBar.qml
        ScrollView.qml
        TextArea.qml
        TextEditMenu.qml
        TextField.qml
        TextMenuTap.qml
        Theme.qml
        ToolBar.qml
        ToolTip.qml
    SOURCES
        host_accent.h
        host_accent.cpp
        legacy_windows.h
        legacy_windows.cpp
        menu_drag.h
        menu_drag.cpp
        symbol_tint.h
        symbol_tint.cpp
        system_accent.h
        system_accent.cpp
        text_menu_support.h
        text_menu_support.cpp
        touch_frontend.h
        ${cerfqt_style_host_sources}
        window_insets.h
        window_insets.cpp)
target_link_libraries(cerfqt_style PRIVATE Qt6::Quick)
if(APPLE)
    target_link_libraries(cerfqt_style PRIVATE "-framework AppKit")
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(Qt6 REQUIRED COMPONENTS DBus)
    target_link_libraries(cerfqt_style PRIVATE Qt6::DBus)
endif()
