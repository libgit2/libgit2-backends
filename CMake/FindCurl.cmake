# - Try to find the curl library
# Once done this will define
#
#  CURL_FOUND - System has curl
#  CURL_INCLUDE_DIR - The curl include directory
#  CURL_LIBRARIES - The libraries needed to use curl
#  CURL_DEFINITIONS - Compiler switches required for using curl


# use pkg-config to get the directories and then use these values
# in the FIND_PATH() and FIND_LIBRARY() calls
#FIND_PACKAGE(PkgConfig)
#PKG_SEARCH_MODULE(PC_CURL curl)

SET(CURL_DEFINITIONS ${PC_CURL_CFLAGS_OTHER})

FIND_PATH(CURL_INCLUDE_DIR NAMES curl/curl.h
   HINTS
   ${PC_CURL_INCLUDEDIR}
   ${PC_CURL_INCLUDE_DIRS}
)

FIND_LIBRARY(CURL_LIBRARIES NAMES curl
   HINTS
   ${PC_CURL_LIBDIR}
   ${PC_CURL_LIBRARY_DIRS}
)


INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(curl DEFAULT_MSG CURL_LIBRARIES CURL_INCLUDE_DIR)

MARK_AS_ADVANCED(CURL_INCLUDE_DIR CURL_LIBRARIES)