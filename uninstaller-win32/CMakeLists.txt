cerf_read_string_define(uninstaller_name "${CERF_EXECUTABLE_NAMES_HEADER}" CERF_UNINSTALLER_NAME)
add_executable(uninstaller-win32 WIN32
    uninstall_main.cpp
    uninstall_dialogs.cpp
    uninstall_removal.cpp
    process_wait.cpp
    shell_integration_windows.cpp
    "${CMAKE_SOURCE_DIR}/cerf-qt/cerfman/path_removal.cpp"
    "${CMAKE_SOURCE_DIR}/cerf-qt/cerfman/wait_for_pid.cpp"
    "${CMAKE_SOURCE_DIR}/libCerfCore/src/core/utf16.cpp"
    "${CMAKE_SOURCE_DIR}/libCerfCore/src/platform/host_error_win32.cpp"
    "${CMAKE_SOURCE_DIR}/libCerfCore/src/platform/host_process_win32.cpp"
    uninstall.rc
    uninstall.manifest)
set_target_properties(uninstaller-win32 PROPERTIES OUTPUT_NAME "${uninstaller_name}")
target_compile_features(uninstaller-win32 PRIVATE cxx_std_20)
target_compile_definitions(uninstaller-win32 PRIVATE UNICODE _UNICODE)
target_include_directories(uninstaller-win32 PRIVATE "${CERF_GENERATED_DIR}" "${CMAKE_SOURCE_DIR}/libCerfCore/include")
target_link_libraries(uninstaller-win32 PRIVATE comctl32 ole32 shell32 advapi32 uuid)
if(MSVC)
    target_compile_options(uninstaller-win32 PRIVATE /permissive- /utf-8 /W4 /WX)
endif()
set_target_properties(uninstaller-win32 PROPERTIES MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
