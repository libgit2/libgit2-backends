PROJECT(libgit2-redis C)
CMAKE_MINIMUM_REQUIRED(VERSION 2.6)

INCLUDE(../CMake/FindHiredis.cmake)

# Build options
OPTION (BUILD_SHARED_LIBS "Build Shared Library (OFF for Static)" ON)
OPTION (BUILD_TESTS "Build Tests" ON)
SET (PC_LIBGIT2_LIBRARY_DIRS "" CACHE STRING "libgit2 path")
SET (PC_LIBGIT2_INCLUDE_DIRS "" CACHE STRING "libgit2 include directories")

# Allow overriding to local libgit2. I'm pretty sure I'm doing this wrong.
IF (${PC_LIBGIT2_INCLUDE_DIRS} STREQUAL "")
  INCLUDE(../CMake/FindLibgit2.cmake)
ELSE ()
  SET (LIBGIT2_LIBRARIES ${PC_LIBGIT2_LIBRARY_DIRS})
  SET (LIBGIT2_INCLUDE_DIRS ${PC_LIBGIT2_INCLUDE_DIRS})
ENDIF ()

# Build Release by default
IF (NOT CMAKE_BUILD_TYPE)
    SET(CMAKE_BUILD_TYPE "Release" CACHE STRING "Choose the type of build, options are: Debug Release RelWithDebInfo MinSizeRel." FORCE)
ENDIF ()

# Compile and link libgit2
INCLUDE_DIRECTORIES(${LIBGIT2_INCLUDE_DIRS} ${LIBHIREDIS_INCLUDE_DIRS})

ADD_LIBRARY(core OBJECT hiredis.c)
IF (BUILD_SHARED_LIBS)
    ADD_LIBRARY(git2-redis SHARED $<TARGET_OBJECTS:core>)
ELSE ()
    ADD_LIBRARY(git2-redis STATIC $<TARGET_OBJECTS:core>)
ENDIF ()

TARGET_LINK_LIBRARIES(git2-redis ${LIBGIT2_LIBRARIES} ${LIBHIREDIS_LIBRARIES})
