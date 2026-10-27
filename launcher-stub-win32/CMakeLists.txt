string(REGEX REPLACE "/RTC[1csu]*" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
string(REPLACE "/EHsc" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

cerf_read_string_define(launcher_name "${CERF_EXECUTABLE_NAMES_HEADER}" CERF_LAUNCHER_NAME)
add_executable(launcher-stub-win32 WIN32 launcher_stub.cpp launcher_stub.rc)
set_target_properties(launcher-stub-win32 PROPERTIES OUTPUT_NAME "${launcher_name}")
target_compile_features(launcher-stub-win32 PRIVATE cxx_std_20)
target_compile_definitions(launcher-stub-win32 PRIVATE UNICODE _UNICODE)
target_include_directories(launcher-stub-win32 PRIVATE "${CERF_GENERATED_DIR}" "${CMAKE_SOURCE_DIR}/libCerfCore/include")
target_compile_options(launcher-stub-win32 PRIVATE /O1 /GS- /W4 /WX /permissive-)
target_link_options(launcher-stub-win32 PRIVATE /NODEFAULTLIB /ENTRY:StubEntry
                    "/MANIFESTUAC:level='asInvoker' uiAccess='false'")
target_link_libraries(launcher-stub-win32 PRIVATE kernel32 user32 shell32)
