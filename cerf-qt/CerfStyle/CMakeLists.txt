qt_add_library(cerfqt_style STATIC)
set_source_files_properties(Theme.qml PROPERTIES QT_QML_SINGLETON_TYPE TRUE)
set(cerfqt_style_host_sources touch_frontend_default.cpp touch_frontend_android.cpp)
cerfcore_select_host_sources(cerfqt_style_host_sources)
qt_add_qml_module(cerfqt_style
    URI CerfStyle
    VERSION 1.0
    QML_FILES
        ApplicationWindow.qml
        Button.qml
        ComboBox.qml
        Dialog.qml
        FieldBackground.qml
        Menu.qml
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
        legacy_windows.h
        legacy_windows.cpp
        symbol_tint.h
        symbol_tint.cpp
        text_menu_support.h
        text_menu_support.cpp
        touch_frontend.h
        ${cerfqt_style_host_sources}
        window_insets.h
        window_insets.cpp)
target_link_libraries(cerfqt_style PRIVATE Qt6::Quick)
