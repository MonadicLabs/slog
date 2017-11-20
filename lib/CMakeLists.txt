cmake_minimum_required(VERSION 2.8)
project (LIBSLOG C)

set( CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${PROJECT_SOURCE_DIR}/cmake")

include_directories(${LIBSLOG_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${LIBSLOG_SOURCE_DIR}/extdeps/concurrentqueue)

# SET( CMAKE_C_FLAGS  "${CMAKE_C_FLAGS} -std=c99" )

# mBed TLS
add_subdirectory( extdeps/mbedtls )
INCLUDE_DIRECTORIES( ${LIBSLOG_SOURCE_DIR}/extdeps/mbedtls/include )
LINK_DIRECTORIES( ${LIBSLOG_BINARY_DIR}/extdeps/mbedtls/library )
set( DEPS "${DEPS};mbedtls;mbedcrypto" )

# Heatshrink
INCLUDE_DIRECTORIES( ${LIBSLOG_SOURCE_DIR}/extdeps/heatshrink )
file (GLOB_RECURSE HEATSHRINK_SRC ${LIBSLOG_SOURCE_DIR}/extdeps/heatshrink/heatshrink_*.c )

# LIBRARY SOURCE CODE
file (GLOB_RECURSE SLOG_SRC ${LIBSLOG_SOURCE_DIR}/src/*.c)
file (GLOB_RECURSE SLOG_HEADERS ${LIBSLOG_SOURCE_DIR}/include/*.h)

add_library(slog STATIC ${SLOG_SRC} ${SLOG_HEADERS} ${POPOPO} ${HEATSHRINK_SRC} )
add_dependencies( slog mbedtls )
add_dependencies( slog mbedcrypto )


target_link_libraries( slog ${DEPS} )
