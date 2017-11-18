cmake_minimum_required(VERSION 2.8)
project (LIBSLOG C)

set( CMAKE_MODULE_PATH "${CMAKE_MODULE_PATH};${PROJECT_SOURCE_DIR}/cmake")

include_directories(${LIBSLOG_SOURCE_DIR}/include)
INCLUDE_DIRECTORIES(${LIBSLOG_SOURCE_DIR}/extdeps/concurrentqueue)

# SET( CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -pthread" )

# LIBRARY SOURCE CODE
file (GLOB_RECURSE SLOG_SRC ${LIBSLOG_SOURCE_DIR}/src/*.c)
file (GLOB_RECURSE SLOG_HEADERS ${LIBSLOG_SOURCE_DIR}/include/*.h)

add_library(slog SHARED ${SLOG_SRC} ${SLOG_HEADERS} )

target_link_libraries( slog ${DEPS} )
