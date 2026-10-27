cmake_minimum_required(VERSION 3.25)
project(cerfqt LANGUAGES CXX)

if(ANDROID)
    find_package(Qt6 6.8 REQUIRED COMPONENTS Svg Network Qml Quick QuickControls2)
else()
    find_package(Qt6 6.8 REQUIRED COMPONENTS Widgets Svg Network Qml Quick QuickControls2)
endif()
find_package(libzip CONFIG REQUIRED)
qt_standard_project_setup(REQUIRES 6.8)
add_subdirectory(CerfStyle)

file(TO_CMAKE_PATH "${CERFQT_RESVG_PREFIX}" cerfqt_resvg_prefix)
if(MSVC)
    set(cerfqt_resvg_library "${cerfqt_resvg_prefix}/lib/resvg.lib")
else()
    set(cerfqt_resvg_library "${cerfqt_resvg_prefix}/lib/libresvg.a")
endif()
file(STRINGS "${cerfqt_resvg_prefix}/link_libraries.txt" cerfqt_resvg_link_libraries)
add_library(cerfqt_resvg STATIC IMPORTED)
set_target_properties(cerfqt_resvg PROPERTIES
    IMPORTED_CONFIGURATIONS RELEASE
    IMPORTED_LOCATION "${cerfqt_resvg_library}"
    IMPORTED_LOCATION_RELEASE "${cerfqt_resvg_library}"
    INTERFACE_INCLUDE_DIRECTORIES "${cerfqt_resvg_prefix}/include"
    INTERFACE_LINK_LIBRARIES "${cerfqt_resvg_link_libraries}")

if(ANDROID)
    set(cerfqt_frontend_dir mobile)
else()
    set(cerfqt_frontend_dir desktop)
endif()
file(GLOB cerfqt_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp"
     "${CMAKE_CURRENT_SOURCE_DIR}/cerfman/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/${cerfqt_frontend_dir}/*.cpp")
if(APPLE)
    enable_language(OBJCXX)
    file(GLOB cerfqt_objcxx_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*_macos.mm")
    list(APPEND cerfqt_sources ${cerfqt_objcxx_sources})
endif()
cerfcore_select_host_sources(cerfqt_sources)

qt_add_executable(cerf-qt ${cerfqt_sources})
target_compile_features(cerf-qt PRIVATE cxx_std_20)
target_include_directories(cerf-qt PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/cerfman"
                                           "${CMAKE_CURRENT_SOURCE_DIR}/${cerfqt_frontend_dir}")
target_link_libraries(cerf-qt PRIVATE
    "$<LINK_LIBRARY:WHOLE_ARCHIVE,cerfcore::cerfcore>"
    Qt6::Svg
    Qt6::Network
    Qt6::Quick
    Qt6::QuickControls2
    libzip::zip
    cerfqt_resvg
    cerfqt_style
    cerfqt_styleplugin)
if(NOT ANDROID)
    target_link_libraries(cerf-qt PRIVATE Qt6::Widgets)
endif()

file(GLOB cerfman_qml CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/cerfman/qml/*.qml"
     "${CMAKE_CURRENT_SOURCE_DIR}/${cerfqt_frontend_dir}/qml/*.qml")
foreach(cerfman_file IN LISTS cerfman_qml)
    get_filename_component(cerfman_alias "${cerfman_file}" NAME)
    set_source_files_properties("${cerfman_file}" PROPERTIES QT_RESOURCE_ALIAS "${cerfman_alias}")
endforeach()
set_source_files_properties("${CMAKE_CURRENT_SOURCE_DIR}/cerfman/qml/Dialogs.qml" PROPERTIES QT_QML_SINGLETON_TYPE TRUE)
cerf_read_string_define(cerfqt_manager_qml_module "${CERF_RESOURCE_PATHS_HEADER}" CERF_MANAGER_QML_MODULE)
qt_add_qml_module(cerf-qt
    URI ${cerfqt_manager_qml_module}
    VERSION 1.0
    QML_FILES ${cerfman_qml})
qt_add_resources(cerf-qt "cerfqt_controls_conf"
    PREFIX "/"
    FILES qtquickcontrols2.conf)

set(cerfqt_resource_paths "${CERF_RESOURCE_PATHS_HEADER}")
cerf_read_string_define(cerfqt_symbol_icons_prefix "${cerfqt_resource_paths}" CERF_SYMBOL_ICONS_PREFIX)
cerf_read_string_define(cerfqt_install_prefix "${cerfqt_resource_paths}" CERF_INSTALL_RESOURCE_PREFIX)
cerf_read_string_define(cerfqt_asset_icons_dir "${cerfqt_resource_paths}" CERF_ASSET_ICONS_DIR)
cerf_read_string_define(cerfqt_fonts_dir "${cerfqt_resource_paths}" CERF_FONTS_DIR)
cerf_read_string_define(cerfqt_font_sans "${cerfqt_resource_paths}" CERF_FONT_SANS)
cerf_read_string_define(cerfqt_font_sans_bold "${cerfqt_resource_paths}" CERF_FONT_SANS_BOLD)
cerf_read_string_define(cerfqt_font_mono_bold "${cerfqt_resource_paths}" CERF_FONT_MONO_BOLD)
cerf_read_string_define(cerfqt_contributors_file "${cerfqt_resource_paths}" CERF_CONTRIBUTORS_FILE)

set(cerfman_symbols "${CMAKE_CURRENT_SOURCE_DIR}/../external/material_symbols")
file(GLOB cerfman_icons CONFIGURE_DEPENDS "${cerfman_symbols}/*.svg")
qt_add_resources(cerf-qt "cerfman_icons"
    PREFIX "${cerfqt_symbol_icons_prefix}"
    BASE "${cerfman_symbols}"
    FILES ${cerfman_icons})
if(APPLE)
    target_link_libraries(cerf-qt PRIVATE "-framework Foundation")
endif()
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    find_package(Qt6 REQUIRED COMPONENTS DBus)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(cerfqt_screen REQUIRED IMPORTED_TARGET xcb xcb-randr wayland-client)
    target_link_libraries(cerf-qt PRIVATE Qt6::DBus PkgConfig::cerfqt_screen)
    enable_language(C)
    find_program(cerfqt_wayland_scanner wayland-scanner REQUIRED)
    set(cerfqt_xdg_output_xml "${CMAKE_CURRENT_SOURCE_DIR}/../external/wayland_protocols/xdg-output-unstable-v1.xml")
    set(cerfqt_wayland_dir "${CMAKE_CURRENT_BINARY_DIR}/wayland")
    set(cerfqt_xdg_output_header "${cerfqt_wayland_dir}/xdg-output-unstable-v1-client-protocol.h")
    set(cerfqt_xdg_output_code "${cerfqt_wayland_dir}/xdg-output-unstable-v1-protocol.c")
    file(MAKE_DIRECTORY "${cerfqt_wayland_dir}")
    add_custom_command(
        OUTPUT "${cerfqt_xdg_output_header}" "${cerfqt_xdg_output_code}"
        COMMAND "${cerfqt_wayland_scanner}" client-header "${cerfqt_xdg_output_xml}" "${cerfqt_xdg_output_header}"
        COMMAND "${cerfqt_wayland_scanner}" private-code "${cerfqt_xdg_output_xml}" "${cerfqt_xdg_output_code}"
        DEPENDS "${cerfqt_xdg_output_xml}"
        VERBATIM)
    target_sources(cerf-qt PRIVATE "${cerfqt_xdg_output_header}" "${cerfqt_xdg_output_code}")
    target_include_directories(cerf-qt PRIVATE "${cerfqt_wayland_dir}")
    set_target_properties(cerf-qt cerfqt_style PROPERTIES QT_QMLCACHEGEN_ARGUMENTS "--only-bytecode")
    foreach(cerfqt_target IN ITEMS cerf-qt cerfqt_style cerfqt_styleplugin)
        target_compile_options(${cerfqt_target} PRIVATE
            $<$<CXX_COMPILER_ID:GNU>:-mno-direct-extern-access>
            $<$<CXX_COMPILER_ID:Clang>:-fno-direct-access-external-data>)
    endforeach()
endif()

set(cerfqt_assets "${CMAKE_CURRENT_SOURCE_DIR}/../assets")
file(GLOB cerfqt_icons CONFIGURE_DEPENDS "${cerfqt_assets}/${cerfqt_asset_icons_dir}/*.svg")
qt_add_resources(cerf-qt "cerfqt_assets"
    PREFIX "/"
    BASE "${cerfqt_assets}"
    FILES
        ${cerfqt_icons}
        "${cerfqt_assets}/${cerfqt_contributors_file}"
        "${cerfqt_assets}/${cerfqt_fonts_dir}/${cerfqt_font_sans}"
        "${cerfqt_assets}/${cerfqt_fonts_dir}/${cerfqt_font_sans_bold}"
        "${cerfqt_assets}/${cerfqt_fonts_dir}/${cerfqt_font_mono_bold}")

cerf_read_string_define(cerfqt_frontend_name "${CERF_EXECUTABLE_NAMES_HEADER}" CERF_FRONTEND_NAME)
cerf_read_string_define(cerfqt_product_name
                        "${CMAKE_CURRENT_SOURCE_DIR}/../libCerfCore/include/cerfcore/core/product_name_text.h"
                        CERF_PRODUCT_NAME)
cerf_read_string_define(cerfqt_db_json_name "${CERF_INSTALL_LAYOUT_HEADER}" CERF_DB_JSON_NAME)
cerf_read_string_define(cerfqt_ce_apps_name "${CERF_INSTALL_LAYOUT_HEADER}" CERF_CE_APPS_DIR_NAME)
cerf_read_string_define(cerfqt_global_config_name "${CERF_INSTALL_ROOT_HEADER}" CERF_GLOBAL_CONFIG_NAME)
cerf_read_string_define(cerfqt_license_name "${CERF_INSTALL_ROOT_HEADER}" CERF_LICENSE_NAME)
cerf_read_string_define(cerfqt_notices_name "${CERF_INSTALL_ROOT_HEADER}" CERF_NOTICES_NAME)
cerf_read_string_define(cerfqt_licenses_dir_name "${CERF_INSTALL_ROOT_HEADER}" CERF_LICENSES_DIR_NAME)
set(cerfqt_db_json "${CMAKE_CURRENT_SOURCE_DIR}/../libCerfCore/${cerfqt_db_json_name}")
if(NOT APPLE)
    set_target_properties(cerf-qt PROPERTIES OUTPUT_NAME "${cerfqt_frontend_name}")
endif()
if(WIN32)
    target_sources(cerf-qt PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/cerf.rc"
                                   "${CMAKE_CURRENT_SOURCE_DIR}/../uninstaller-win32/process_wait.cpp"
                                   "${CMAKE_CURRENT_SOURCE_DIR}/../uninstaller-win32/shell_integration_windows.cpp")
    set_target_properties(cerf-qt PROPERTIES WIN32_EXECUTABLE TRUE)
    target_link_libraries(cerf-qt PRIVATE ole32 shell32 advapi32 uuid)
endif()

if(MSVC)
    target_compile_options(cerf-qt PRIVATE /permissive- /utf-8 /MP)
    target_link_options(cerf-qt PRIVATE /DEBUG
                        "/PDBSTRIPPED:$<TARGET_FILE_DIR:cerf-qt>/${cerfqt_frontend_name}.public.pdb"
                        "$<$<CONFIG:Release>:/OPT:REF>" "$<$<CONFIG:Release>:/OPT:ICF>")
    set_source_files_properties(${cerfqt_sources} PROPERTIES COMPILE_OPTIONS "/W4;/WX")
else()
    set_source_files_properties(${cerfqt_sources} PROPERTIES COMPILE_OPTIONS
                                "-Wall;-Wextra;-Werror")
    set_target_properties(cerf-qt PROPERTIES ENABLE_EXPORTS ON)
endif()

target_include_directories(cerf-qt PRIVATE "${CERF_GENERATED_DIR}")

if(APPLE)
    foreach(cerfqt_part MAJOR MINOR PATCH)
        cerf_read_int_define(cerfqt_version_${cerfqt_part} "${CMAKE_CURRENT_SOURCE_DIR}/version.h"
                             CERF_VERSION_${cerfqt_part})
    endforeach()
    set(cerfqt_version "${cerfqt_version_MAJOR}.${cerfqt_version_MINOR}.${cerfqt_version_PATCH}")
    cerf_read_string_define(cerfqt_logo_asset "${CERF_RESOURCE_PATHS_HEADER}" CERF_LOGO_ASSET)
    cerf_read_int_define(cerfqt_logo_px "${CERF_RESOURCE_PATHS_HEADER}" CERF_LOGO_PX)
    set(cerfqt_logo_png "${cerfqt_assets}/${cerfqt_logo_asset}_${cerfqt_logo_px}.png")
    set(cerfqt_icns "${CMAKE_CURRENT_BINARY_DIR}/icns/cerf.icns")
    add_custom_command(OUTPUT "${cerfqt_icns}"
        COMMAND Python3::Interpreter "${CMAKE_CURRENT_SOURCE_DIR}/../tools/macos_icns.py"
                "${cerfqt_logo_png}" "${cerfqt_icns}"
        DEPENDS "${cerfqt_logo_png}"
                "${CMAKE_CURRENT_SOURCE_DIR}/../tools/macos_icns.py"
        VERBATIM)
    target_sources(cerf-qt PRIVATE "${cerfqt_icns}")
    set_source_files_properties("${cerfqt_icns}" PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
    set_target_properties(cerf-qt PROPERTIES
        MACOSX_BUNDLE TRUE
        OUTPUT_NAME "${cerfqt_product_name}"
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.in"
        MACOSX_BUNDLE_BUNDLE_NAME "${cerfqt_product_name}"
        MACOSX_BUNDLE_GUI_IDENTIFIER "cx.cerf.emulator"
        MACOSX_BUNDLE_ICON_FILE "cerf.icns"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${cerfqt_version}"
        MACOSX_BUNDLE_BUNDLE_VERSION "${cerfqt_version}")
    set(cerfqt_output_dir "$<TARGET_BUNDLE_DIR:cerf-qt>/..")
else()
    set(cerfqt_output_dir "$<TARGET_FILE_DIR:cerf-qt>")
endif()

if(ANDROID)
    set(cerfqt_install_dir "${CMAKE_CURRENT_BINARY_DIR}/install")
    set(cerfqt_global_config "${cerfqt_install_dir}/${cerfqt_global_config_name}")
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/../bundled/${cerfqt_global_config_name}" "${cerfqt_global_config}"
                   COPYONLY)
    execute_process(COMMAND "${Python3_EXECUTABLE}" "${CERF_HOST_BRANCH_PY}"
                            --stamp "${cerfqt_global_config}" "${CERFQT_HOST_BRANCH}"
                    RESULT_VARIABLE cerfqt_stamp_rc)
    if(NOT cerfqt_stamp_rc EQUAL 0)
        message(FATAL_ERROR "tools/host_branch.py --stamp failed (${cerfqt_stamp_rc})")
    endif()
    configure_file("${cerfqt_db_json}" "${cerfqt_install_dir}/${cerfqt_db_json_name}" COPYONLY)
    qt_add_resources(cerf-qt "cerfqt_install"
        PREFIX "${cerfqt_install_prefix}"
        BASE "${cerfqt_install_dir}"
        FILES "${cerfqt_global_config}" "${cerfqt_install_dir}/${cerfqt_db_json_name}")
    file(TO_CMAKE_PATH "${CERFQT_ANDROID_CE_APPS_DIR}" cerfqt_ce_apps_dir)
    file(GLOB_RECURSE cerfqt_ce_apps CONFIGURE_DEPENDS "${cerfqt_ce_apps_dir}/*")
    qt_add_resources(cerf-qt "cerfqt_ce_apps"
        PREFIX "${cerfqt_install_prefix}/${cerfqt_ce_apps_name}"
        BASE "${cerfqt_ce_apps_dir}"
        FILES ${cerfqt_ce_apps})
    set(cerfqt_repo_dir "${CMAKE_CURRENT_SOURCE_DIR}/..")
    file(GLOB cerfqt_licenses CONFIGURE_DEPENDS "${cerfqt_repo_dir}/${cerfqt_licenses_dir_name}/*")
    qt_add_resources(cerf-qt "cerfqt_notices"
        PREFIX "${cerfqt_install_prefix}"
        BASE "${cerfqt_repo_dir}"
        FILES "${cerfqt_repo_dir}/${cerfqt_license_name}" "${cerfqt_repo_dir}/${cerfqt_notices_name}"
              ${cerfqt_licenses})
    set_property(TARGET cerf-qt APPEND PROPERTY QT_ANDROID_EXTRA_LIBS ${CERFQT_ANDROID_EXTRA_LIBS})
    set_target_properties(cerf-qt PROPERTIES
        QT_ANDROID_PACKAGE_NAME "cx.cerf"
        QT_ANDROID_APP_NAME "${cerfqt_product_name}"
        QT_ANDROID_PACKAGE_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/mobile/android"
        QT_ANDROID_APP_ICON "@mipmap/ic_launcher"
        QT_ANDROID_MIN_SDK_VERSION ${CERFQT_ANDROID_MIN_SDK}
        QT_ANDROID_TARGET_SDK_VERSION ${CERFQT_ANDROID_TARGET_SDK})
    qt_add_android_permission(cerf-qt NAME android.permission.RECORD_AUDIO)
else()
    add_custom_target(cerf-qt-bundled ALL
        COMMAND "${CMAKE_COMMAND}"
                "-DCERFQT_BUNDLED_DIR=${CMAKE_CURRENT_SOURCE_DIR}/../bundled"
                "-DCERFQT_DB_JSON=${cerfqt_db_json}"
                "-DCERFQT_DB_JSON_NAME=${cerfqt_db_json_name}"
                "-DCERFQT_OUTPUT_DIR=${cerfqt_output_dir}"
                -P "${CMAKE_CURRENT_SOURCE_DIR}/copy_bundled.cmake"
        VERBATIM)
    add_dependencies(cerf-qt-bundled cerf-qt)
endif()
