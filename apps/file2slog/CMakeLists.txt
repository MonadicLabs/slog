cmake_minimum_required(VERSION 2.8)
project(SLOG_FILE2SLOG C)

include_directories(${LIBSLOG_SOURCE_DIR}/include)

# Add lib
LINK_DIRECTORIES(${LIBSLOG_BINARY_DIR})
set( DEPS "${DEPS};slog" )

# Global shit
file (GLOB_RECURSE SLOG_FILE2SLOG_SRC ./*.c)
add_executable(file2slog ${SLOG_FILE2SLOG_SRC})

target_link_libraries (file2slog ${DEPS} )
