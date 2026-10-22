cmake_minimum_required(VERSION 3.25)
project(cerfqt LANGUAGES CXX)

find_package(Qt6 REQUIRED COMPONENTS Widgets Svg)

file(GLOB cerfqt_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    list(FILTER cerfqt_sources EXCLUDE REGEX "_linux\\.cpp$")
endif()
if(APPLE)
    enable_language(OBJCXX)
    file(GLOB cerfqt_objcxx_sources CONFIGURE_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/*_macos.mm")
    list(APPEND cerfqt_sources ${cerfqt_objcxx_sources})
else()
    list(FILTER cerfqt_sources EXCLUDE REGEX "_macos\\.cpp$")
endif()

add_executable(cerf-qt ${cerfqt_sources})
target_compile_features(cerf-qt PRIVATE cxx_std_20)
target_link_libraries(cerf-qt PRIVATE
    "$<LINK_LIBRARY:WHOLE_ARCHIVE,cerffrontend::cerffrontend>"
    Qt6::Widgets
    Qt6::Svg)
if(APPLE)
    target_link_libraries(cerf-qt PRIVATE "-framework Foundation")
endif()

set(cerfqt_assets "${CMAKE_CURRENT_SOURCE_DIR}/../assets")
file(GLOB cerfqt_icons CONFIGURE_DEPENDS "${cerfqt_assets}/icons_sources/*.svg")
qt_add_resources(cerf-qt "cerfqt_assets"
    PREFIX "/"
    BASE "${cerfqt_assets}"
    FILES
        ${cerfqt_icons}
        "${cerfqt_assets}/cerf_1024.png"
        "${cerfqt_assets}/fonts/IBMPlexSans-Regular.ttf"
        "${cerfqt_assets}/fonts/IBMPlexSans-Bold.ttf"
        "${cerfqt_assets}/fonts/IBMPlexMono-Bold.ttf")

if(MSVC)
    target_compile_options(cerf-qt PRIVATE /W4 /WX /permissive- /utf-8)
else()
    target_compile_options(cerf-qt PRIVATE -Wall -Wextra -Werror)
    set_target_properties(cerf-qt PROPERTIES ENABLE_EXPORTS ON)
endif()

if(APPLE)
    find_package(Python3 REQUIRED COMPONENTS Interpreter)
    file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/../libCerfFrontend/include/cerffrontend/version.h"
         cerfqt_version_defines REGEX "#define CERF_VERSION_(MAJOR|MINOR|PATCH) ")
    foreach(cerfqt_line IN LISTS cerfqt_version_defines)
        string(REGEX MATCH "CERF_VERSION_([A-Z]+) +([0-9]+)" cerfqt_match "${cerfqt_line}")
        set(cerfqt_version_${CMAKE_MATCH_1} "${CMAKE_MATCH_2}")
    endforeach()
    set(cerfqt_version "${cerfqt_version_MAJOR}.${cerfqt_version_MINOR}.${cerfqt_version_PATCH}")
    set(cerfqt_icns "${CMAKE_CURRENT_BINARY_DIR}/icns/cerf.icns")
    add_custom_command(OUTPUT "${cerfqt_icns}"
        COMMAND Python3::Interpreter "${CMAKE_CURRENT_SOURCE_DIR}/../tools/macos_icns.py"
                "${cerfqt_assets}/cerf_running_1024.png" "${cerfqt_icns}"
        DEPENDS "${cerfqt_assets}/cerf_running_1024.png"
                "${CMAKE_CURRENT_SOURCE_DIR}/../tools/macos_icns.py"
        VERBATIM)
    target_sources(cerf-qt PRIVATE "${cerfqt_icns}")
    set_source_files_properties("${cerfqt_icns}" PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
    set_target_properties(cerf-qt PROPERTIES
        MACOSX_BUNDLE TRUE
        OUTPUT_NAME "CE Runtime Foundation"
        MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/Info.plist.in"
        MACOSX_BUNDLE_BUNDLE_NAME "CE Runtime Foundation"
        MACOSX_BUNDLE_GUI_IDENTIFIER "cx.cerf.emulator"
        MACOSX_BUNDLE_ICON_FILE "cerf.icns"
        MACOSX_BUNDLE_SHORT_VERSION_STRING "${cerfqt_version}"
        MACOSX_BUNDLE_BUNDLE_VERSION "${cerfqt_version}")
    set(cerfqt_output_dir "$<TARGET_BUNDLE_DIR:cerf-qt>/..")
else()
    set(cerfqt_output_dir "$<TARGET_FILE_DIR:cerf-qt>")
endif()

add_custom_target(cerf-qt-bundled ALL
    COMMAND "${CMAKE_COMMAND}"
            "-DCERFQT_BUNDLED_DIR=${CMAKE_CURRENT_SOURCE_DIR}/../bundled"
            "-DCERFQT_DB_JSON=${CMAKE_CURRENT_SOURCE_DIR}/../libCerfCore/db.json"
            "-DCERFQT_OUTPUT_DIR=${cerfqt_output_dir}"
            -P "${CMAKE_CURRENT_SOURCE_DIR}/copy_bundled.cmake"
    VERBATIM)
add_dependencies(cerf-qt-bundled cerf-qt)
