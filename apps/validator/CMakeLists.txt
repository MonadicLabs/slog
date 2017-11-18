cmake_minimum_required(VERSION 2.8)
project(SLOG_VALIDATOR C)

include_directories(${LIBSLOG_SOURCE_DIR}/include)

# Add lib
LINK_DIRECTORIES(${LIBSLOG_BINARY_DIR})
set( DEPS "${DEPS};slog" )

# Global shit
file (GLOB_RECURSE SLOG_VALIDATOR_SRC ./*.c)
add_executable(slog_validator ${SLOG_VALIDATOR_SRC})

target_link_libraries (slog_validator ${DEPS} )
