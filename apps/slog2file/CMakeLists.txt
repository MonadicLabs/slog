cmake_minimum_required(VERSION 2.8)
project(SLOG2FILE C)

include_directories(${LIBSLOG_SOURCE_DIR}/include)

# Add lib
LINK_DIRECTORIES(${LIBSLOG_BINARY_DIR})
set( DEPS "${DEPS};slog" )

# Global shit
file (GLOB_RECURSE SLOG_SLOG2FILE_SRC ./*.c)
add_executable(slog2file ${SLOG_SLOG2FILE_SRC})

target_link_libraries (slog2file ${DEPS} )
