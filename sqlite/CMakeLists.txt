PROJECT(LIBGIT2-sqlite C)
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

INCLUDE(../CMake/FindLibgit2.cmake)
INCLUDE(../CMake/FindSQLite3.cmake)

# Build options
OPTION (BUILD_SHARED_LIBS "Build Shared Library (OFF for Static)" ON)
OPTION (BUILD_TESTS "Build Tests" ON)

# Build Release by default
IF (NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
ENDIF ()

# Compile and link LIBGIT2
INCLUDE_DIRECTORIES(${LIBGIT2_INCLUDE_DIRS} ${SQLITE3_INCLUDE_DIRS})
ADD_LIBRARY(git2-sqlite sqlite.c)
TARGET_LINK_LIBRARIES(git2-sqlite ${LIBGIT2_LIBRARIES} ${SQLITE3_LIBRARIES})
