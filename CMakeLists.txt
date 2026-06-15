cmake_minimum_required(VERSION 3.16)
project(nanos3reader VERSION 0.1.0 LANGUAGES CXX)

# ---------------------------------------------------------------------------------------------------
# nanos3reader — a minimal, read-only S3 range reader (seekable std::istream over HTTP(S) range GETs +
# AWS SigV4), built on libcurl + a small SHA-256. No AWS SDK. See README.md.
# ---------------------------------------------------------------------------------------------------

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)

option(NANOS3READER_BUILD_TESTS    "Build tests (SigV4 known-answer test)" ON)
option(NANOS3READER_BUILD_EXAMPLES "Build the s3cat example"               ON)
set(NANOS3READER_CRYPTO "openssl" CACHE STRING
    "SigV4 SHA-256 backend: openssl (default, links libcrypto) | bundled (in-tree, no crypto link)")

# --- the library --------------------------------------------------------------------------------
add_library(nanos3reader src/s3_reader.cpp)
add_library(nanos3reader::nanos3reader ALIAS nanos3reader)

target_compile_features(nanos3reader PUBLIC cxx_std_17)
target_include_directories(nanos3reader PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

find_package(CURL REQUIRED)
target_link_libraries(nanos3reader PRIVATE CURL::libcurl)

# SigV4 crypto backend. "openssl" links libcrypto for SHA-256; "bundled" uses the in-tree SHA-256 so the
# library links no crypto library of its own (handy for small static builds where libcurl supplies TLS via
# mbedTLS/BearSSL/etc — see README "Small static builds").
if(NANOS3READER_CRYPTO STREQUAL "bundled")
    target_compile_definitions(nanos3reader PRIVATE NANOS3READER_CRYPTO_BUNDLED=1)
    message(STATUS "nanos3reader: bundled SHA-256 (no OpenSSL link)")
else()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(nanos3reader PRIVATE OpenSSL::Crypto)
    message(STATUS "nanos3reader: OpenSSL libcrypto SHA-256")
endif()

# --- example ------------------------------------------------------------------------------------
if(NANOS3READER_BUILD_EXAMPLES)
    add_executable(s3cat examples/s3cat.cpp)
    target_link_libraries(s3cat PRIVATE nanos3reader::nanos3reader)
endif()

# --- tests --------------------------------------------------------------------------------------
if(NANOS3READER_BUILD_TESTS)
    enable_testing()
    add_executable(nanos3reader_sigv4_test tests/sigv4_test.cpp)
    target_link_libraries(nanos3reader_sigv4_test PRIVATE nanos3reader::nanos3reader)
    add_test(NAME sigv4 COMMAND nanos3reader_sigv4_test)
endif()

# --- install / find_package(nanos3reader) -------------------------------------------------------
install(TARGETS nanos3reader EXPORT nanos3readerTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT nanos3readerTargets
        FILE nanos3readerTargets.cmake
        NAMESPACE nanos3reader::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/nanos3reader)

configure_package_config_file(
    cmake/nanos3readerConfig.cmake.in
    "${CMAKE_CURRENT_BINARY_DIR}/nanos3readerConfig.cmake"
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/nanos3reader)
write_basic_package_version_file(
    "${CMAKE_CURRENT_BINARY_DIR}/nanos3readerConfigVersion.cmake"
    VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)
install(FILES
    "${CMAKE_CURRENT_BINARY_DIR}/nanos3readerConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/nanos3readerConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/nanos3reader)
