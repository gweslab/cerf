set(QT_DEPLOY_BIN_DIR .)
set(QT_DEPLOY_LIB_DIR lib)
set(QT_DEPLOY_PLUGINS_DIR plugins)
set(QT_DEPLOY_QML_DIR qml)

file(STRINGS "${CERFQT_DEPLOY_EXCLUDELIST}" cerfqt_excluded_lines REGEX "^[^# \t]")
list(APPEND cerfqt_excluded_lines ld-linux-aarch64.so.1)
set(cerfqt_excluded_regexes "")
set(cerfqt_excluded_names "")
foreach(cerfqt_line IN LISTS cerfqt_excluded_lines)
    string(REGEX REPLACE "[ \t#].*$" "" cerfqt_library "${cerfqt_line}")
    string(REGEX REPLACE "([][+.*()^$])" "\\\\\\1" cerfqt_library "${cerfqt_library}")
    list(APPEND cerfqt_excluded_regexes "/${cerfqt_library}$")
    list(APPEND cerfqt_excluded_names "^${cerfqt_library}$")
endforeach()

qt_deploy_qml_imports(TARGET cerf-qt PLUGINS_FOUND cerfqt_qml_plugins)
file(INSTALL "${CERFQT_DEPLOY_LIBSSL}" DESTINATION "${CMAKE_INSTALL_PREFIX}/${QT_DEPLOY_LIB_DIR}"
     FOLLOW_SYMLINK_CHAIN)
qt_deploy_runtime_dependencies(EXECUTABLE "${CERFQT_DEPLOY_EXECUTABLE}"
    ADDITIONAL_LIBRARIES "${CERFQT_DEPLOY_LIBSSL}"
    ADDITIONAL_MODULES ${cerfqt_qml_plugins}
    INCLUDE_PLUGINS qwayland
    EXCLUDE_PLUGINS qgtk3
    POST_EXCLUDE_REGEXES ${cerfqt_excluded_regexes}
    GENERATE_QT_CONF NO_TRANSLATIONS)

file(GLOB cerfqt_deployed_libraries LIST_DIRECTORIES false "${QT_DEPLOY_PREFIX}/${QT_DEPLOY_LIB_DIR}/*.so*")
set(cerfqt_shipped_libraries "")
foreach(cerfqt_library IN LISTS cerfqt_deployed_libraries)
    if(NOT IS_SYMLINK "${cerfqt_library}")
        list(APPEND cerfqt_shipped_libraries "${cerfqt_library}")
    endif()
endforeach()
foreach(cerfqt_library IN LISTS cerfqt_shipped_libraries)
    execute_process(COMMAND "${CERFQT_DEPLOY_PATCHELF}" --print-rpath "${cerfqt_library}"
                    OUTPUT_VARIABLE cerfqt_runpath OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
    if(NOT cerfqt_runpath STREQUAL "$ORIGIN")
        execute_process(COMMAND "${CERFQT_DEPLOY_PATCHELF}" --set-rpath "$ORIGIN" "${cerfqt_library}"
                        COMMAND_ERROR_IS_FATAL ANY)
    endif()
endforeach()

file(GLOB_RECURSE cerfqt_shipped_modules LIST_DIRECTORIES false
     "${QT_DEPLOY_PREFIX}/${QT_DEPLOY_PLUGINS_DIR}/*.so" "${QT_DEPLOY_PREFIX}/${QT_DEPLOY_QML_DIR}/*.so")
file(GET_RUNTIME_DEPENDENCIES
    EXECUTABLES "${QT_DEPLOY_PREFIX}/${QT_DEPLOY_BIN_DIR}/${CERFQT_DEPLOY_EXECUTABLE_NAME}"
    LIBRARIES ${cerfqt_shipped_libraries}
    MODULES ${cerfqt_shipped_modules}
    PRE_EXCLUDE_REGEXES ${cerfqt_excluded_names}
    RESOLVED_DEPENDENCIES_VAR cerfqt_resolved
    UNRESOLVED_DEPENDENCIES_VAR cerfqt_unresolved
    CONFLICTING_DEPENDENCIES_PREFIX cerfqt_conflicting)
get_filename_component(cerfqt_release_dir "${QT_DEPLOY_PREFIX}" REALPATH)
set(cerfqt_missing ${cerfqt_unresolved} ${cerfqt_conflicting_FILENAMES})
foreach(cerfqt_dependency IN LISTS cerfqt_resolved)
    get_filename_component(cerfqt_dependency_path "${cerfqt_dependency}" REALPATH)
    string(FIND "${cerfqt_dependency_path}" "${cerfqt_release_dir}/" cerfqt_inside)
    if(NOT cerfqt_inside EQUAL 0)
        list(APPEND cerfqt_missing "${cerfqt_dependency}")
    endif()
endforeach()
if(cerfqt_missing)
    list(JOIN cerfqt_missing ", " cerfqt_missing_text)
    message(FATAL_ERROR "The release needs libraries that ${QT_DEPLOY_LIB_DIR}/ does not hold: ${cerfqt_missing_text}")
endif()
