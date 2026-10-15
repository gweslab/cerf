cmake_minimum_required(VERSION 3.20)
project(cerf_i18n_tests LANGUAGES CXX)

find_package(yaml-cpp CONFIG REQUIRED)
add_executable(catalog_test
    catalog_test.cpp
    ../../cerf/i18n/message_format.cpp
    ../../cerf/i18n/translation_catalog.cpp)
target_compile_features(catalog_test PRIVATE cxx_std_20)
target_link_libraries(catalog_test PRIVATE yaml-cpp::yaml-cpp)
if(MSVC)
    target_compile_options(catalog_test PRIVATE /utf-8 /W4)
    set_property(TARGET catalog_test PROPERTY MSVC_RUNTIME_LIBRARY
        "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()
enable_testing()
add_test(NAME catalog_test COMMAND catalog_test
    "${CMAKE_CURRENT_BINARY_DIR}/scratch"
    "${CMAKE_CURRENT_SOURCE_DIR}/../../langs")
